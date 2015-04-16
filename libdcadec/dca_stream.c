/*
 * This file is part of libdcadec.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "common.h"
#include "bitstream.h"
#include "dca_stream.h"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <unistd.h>
#endif

#define BUFFER_ALIGN    4096
#define HEADER_SIZE     16
#define SYNC_SIZE       4

#define AUPR_HDR    UINT64_C(0x415550522D484452)
#define DTSHDHDR    UINT64_C(0x4454534844484452)
#define STRMDATA    UINT64_C(0x5354524D44415441)

struct dcadec_stream {
    void    *fp;
    const struct dcadec_stream_callbacks * cb;

    off_t   stream_size;
    off_t   stream_start;
    off_t   stream_end;

    bool        aupr_present;
    uint32_t    aupr_sample_rate;
    uint32_t    aupr_nframes;
    uint32_t    aupr_nframesamples;
    uint64_t    aupr_npcmsamples;
    uint32_t    aupr_ch_mask;
    uint32_t    aupr_ndelaysamples;

    uint8_t     *buffer;
    size_t      packet_size;
    uint32_t    backup_sync;

    bool    core_plus_exss;
};

// Check for DTS-HD container format. Such files have an extra `blackout'
// frame at the end that we don't wont to parse. Called only if the stream
// is seekable.
static int parse_hd_hdr(struct dcadec_stream *stream)
{
    uint64_t header[2];

    if (stream->cb->read(stream->fp, header, sizeof(header)) != sizeof(header))
        return stream->cb->seek(stream->fp, 0, SEEK_SET);

    if (header[0] != DCA_64BE(DTSHDHDR))
        return stream->cb->seek(stream->fp, 0, SEEK_SET);

    while (true) {
        uint64_t size = DCA_64BE(header[1]);
        if (size > INT64_MAX)
            return -1;

        switch (header[0]) {
        case DCA_64BE(STRMDATA): {
            off_t pos = steam->cb->tell(stream->fp);
            if (pos < 0)
                return -1;
            stream->stream_size = size;
            stream->stream_start = pos;
            stream->stream_end = pos + size;
            return 1;
        }

        case DCA_64BE(AUPR_HDR): {
            uint8_t data[21];

            if (size < sizeof(data))
                return -1;
            if (stream->cb->read(stream->fp, data, sizeof(data)) != sizeof(data))
                return -1;
            if (stream->cb->read(stream->fp, size - sizeof(data), SEEK_CUR) < 0)
                return -1;

            stream->aupr_present = true;

            // Sample rate in Hz
            stream->aupr_sample_rate = DCA_MEM24BE(&data[3]);

            // Number of frames
            stream->aupr_nframes = DCA_MEM32BE(&data[6]);

            // Number of PCM samples per frame
            stream->aupr_nframesamples = DCA_MEM16BE(&data[10]);

            // Number of PCM samples encoded
            stream->aupr_npcmsamples = DCA_MEM40BE(&data[12]);

            // EXSS channel mask
            stream->aupr_ch_mask = DCA_MEM16BE(&data[17]);

            // Codec delay in samples
            stream->aupr_ndelaysamples = DCA_MEM16BE(&data[19]);
            break;
        }

        default:
            if (stream->cb->seek(stream->fp, size, SEEK_CUR) < 0)
                return -1;
            break;
        }

        if (stream->cb->read(stream->fp, header, sizeof(header)) != sizeof(header))
            return -1;
    }

    return 0;
}

DCADEC_API struct dcadec_stream *dcadec_stream_open(const struct dcadec_stream_callbacks * cb, void * opaque)
{
    struct dcadec_stream *stream = ta_znew(NULL, struct dcadec_stream);
    if (!stream)
        return NULL;

    stream->fp = opaque;
    stream->cb = cb;

    if (stream->cb->seek(stream->fp, 0, SEEK_END) == 0) {
        off_t pos = stream->cb->tell(stream->fp);
        if (pos > 0)
            stream->stream_size = pos;
        if (stream->cb->seek(stream->fp, 0, SEEK_SET) < 0)
            goto fail;
        if (pos > 0 && parse_hd_hdr(stream) < 0)
            goto fail;
    }

    if (!(stream->buffer = ta_alloc_size(stream, BUFFER_ALIGN)))
        goto fail;

    return stream;

fail:
    ta_free(stream);
    return NULL;
}

DCADEC_API void dcadec_stream_reset(struct dcadec_stream *stream)
{
    if (stream) {
        if (stream->backup_sync)
            stream->cb->seek(stream->fp, -SYNC_SIZE, SEEK_CUR);
        stream->backup_sync = 0;
    }
}

DCADEC_API void dcadec_stream_close(struct dcadec_stream *stream)
{
    if (stream) {
        ta_free(stream->buffer);
        ta_free(stream);
    }
}

static int realloc_buffer(struct dcadec_stream *stream, size_t size)
{
    size = (size + DCADEC_BUFFER_PADDING + BUFFER_ALIGN - 1) & ~(BUFFER_ALIGN - 1);
    if (ta_get_size(stream->buffer) < size) {
        void *buf = ta_realloc_size(stream, stream->buffer, size);
        if (!buf)
            return -1;
        stream->buffer = buf;
        return 1;
    }
    return 0;
}

static void swap16(uint32_t *data, size_t size)
{
    while (size--) {
        uint32_t v = *data;
        *data++ = ((v & 0x00ff00ff) << 8) | ((v & 0xff00ff00) >> 8);
    }
}

static int read_frame(struct dcadec_stream *stream, uint32_t *sync_p, uint32_t *packed_p)
{
    int packed = 0;
    uint32_t saved_sync;
    size_t packed_size;

    // Stop at position indicated by STRMDATA if known
    if (stream->stream_end > 0 && stream->cb->tell(stream->fp) >= stream->stream_end)
        return 0;

    // Start with a backed up sync word. If there is none, advance one byte at
    // a time until proper sync word is read from the input byte stream.
    uint32_t sync = stream->backup_sync;
    while (sync != SYNC_WORD_CORE
        && sync != SYNC_WORD_EXSS
        && sync != SYNC_WORD_CORE_LE
        && sync != SYNC_WORD_EXSS_LE
        && sync != SYNC_WORD_CORE_14
        && sync != SYNC_WORD_CORE_14_LE) {
        int c = stream->cb->getc(stream->fp);
        if (c == EOF)
            return 0;
        sync = (sync << 8) | c;
    }

    if (sync == SYNC_WORD_CORE_14
        || sync == SYNC_WORD_CORE_14_LE)
    {
        packed = 1;
        saved_sync = sync;
    }

    // Tried to read the second (EXSS) frame and it was core again. Back up
    // the sync word just read and return.
    if ((sync != SYNC_WORD_EXSS && sync != SYNC_WORD_EXSS_LE) && !sync_p) {
        stream->backup_sync = sync;
        return -2;
    }

    // Clear backed up sync word
    stream->backup_sync = 0;

    // Reallocate frame buffer
    if (realloc_buffer(stream, stream->packet_size + HEADER_SIZE) < 0)
        return -1;

    // Read the frame header
    uint8_t *buf = stream->buffer + stream->packet_size;
    if (stream->cb->read(stream->fp, buf + SYNC_SIZE, HEADER_SIZE - SYNC_SIZE) != HEADER_SIZE - SYNC_SIZE)
        return 0;

    if (packed)
    {
        // Store partial sync word so it will be re-packed
        buf[0] = (sync >> 24) & 0xff;
        buf[1] = (sync >> 16) & 0xff;
        buf[2] = (sync >> 8) & 0xff;
        buf[3] = (sync >> 0) & 0xff;
        packed_size = dcadec_stream_pack(buf, buf, HEADER_SIZE / 8, saved_sync);
        sync = DCA_32BE(*(uint32_t*)buf);
    }

    bool swap = false;
    switch (sync) {
    case SYNC_WORD_CORE_LE:
        sync = SYNC_WORD_CORE;
        swap = true;
        break;
    case SYNC_WORD_EXSS_LE:
        sync = SYNC_WORD_EXSS;
        swap = true;
        break;
    }

    if (swap)
        swap16((uint32_t *)buf, HEADER_SIZE / 4);

    struct bitstream bits;

    bits_init(&bits, buf + SYNC_SIZE, HEADER_SIZE - SYNC_SIZE);

    size_t frame_size;

    if (sync == SYNC_WORD_CORE) {
        bool normal_frame = bits_get1(&bits);
        int deficit_samples = bits_get(&bits, 5) + 1;
        if (normal_frame && deficit_samples != 32)
            return -2;
        bits_skip1(&bits);
        int npcmblocks = bits_get(&bits, 7) + 1;
        if (npcmblocks < 6)
            return -2;
        frame_size = bits_get(&bits, 14) + 1;
        if (frame_size < 96)
            return -2;
        if (packed)
            frame_size += frame_size / 7;
    } else {
        bits_skip(&bits, 10);
        bool wide_hdr = bits_get1(&bits);
        bits_skip(&bits, 8 + 4 * wide_hdr);
        frame_size = bits_get(&bits, 16 + 4 * wide_hdr) + 1;
        if (frame_size < HEADER_SIZE)
             return -2;
    }

    // Align frame size to 4-byte boundary
    size_t aligned_size;
    if (packed)
        aligned_size = (frame_size + 7) & ~7;
    else
        aligned_size = (frame_size + 3) & ~3;

    // Reallocate frame buffer
    if (realloc_buffer(stream, stream->packet_size + aligned_size) < 0)
        return -1;

    // Read the rest of the frame
    buf = stream->buffer + stream->packet_size;
    if (stream->cb->read(stream->fp, buf + HEADER_SIZE, frame_size - HEADER_SIZE) != frame_size - HEADER_SIZE)
        return 0;
    if (packed)
    {
        packed_size += dcadec_stream_pack(buf + packed_size, buf + HEADER_SIZE, (frame_size - HEADER_SIZE + 7) / 8, saved_sync);
        frame_size = packed_size;
        aligned_size = (frame_size + 3) & ~3;
    }
    else
    {
        if (swap)
            swap16((uint32_t *)(buf + HEADER_SIZE), (aligned_size - HEADER_SIZE) / 4);
    }

    stream->packet_size += aligned_size;

    // Shut up memcheck
    memset(buf + frame_size, 0, aligned_size - frame_size + DCADEC_BUFFER_PADDING);

    // Restore sync word
    buf[0] = (sync >> 24) & 0xff;
    buf[1] = (sync >> 16) & 0xff;
    buf[2] = (sync >>  8) & 0xff;
    buf[3] = (sync >>  0) & 0xff;

    if (sync_p)
        *sync_p = sync;
    if (packed_p)
        *packed_p = packed;
    return 1;
}

DCADEC_API int dcadec_stream_read(struct dcadec_stream *stream, uint8_t **data, size_t *size, uint32_t * packed_p)
{
    uint32_t sync;
    int ret;

    // Loop until valid DTS core or standalone EXSS frame is read or EOF is
    // reached
    while (true) {
        ret = read_frame(stream, &sync, packed_p);
        if (ret == 1)
            break;
        if (ret == 0)
            return 0;
        if (ret == -2)
            return -DCADEC_EIO;
        if (ret == -1)
            return -DCADEC_ENOMEM;
    }

    // Check for EXSS that may follow core frame and try to concatenate both
    // frames into single packet
    if (sync == SYNC_WORD_CORE) {
        ret = read_frame(stream, NULL, NULL);
        if (ret == -1)
            return -DCADEC_ENOMEM;
        // If the previous frame was core + EXSS, skip the incomplete (core
        // only) frame at end of file
        if (ret == 0 && stream->core_plus_exss)
            return 0;
        stream->core_plus_exss = (ret == 1);
    } else {
        stream->core_plus_exss = false;
    }

    *data = stream->buffer;
    *size = stream->packet_size;

    stream->packet_size = 0;
    return 1;
}

DCADEC_API int dcadec_stream_progress(struct dcadec_stream *stream)
{
    if (stream->stream_size > 0) {
        off_t pos = stream->cb->tell(stream->fp);
        if (pos < stream->stream_start)
            return 0;
        if (pos >= stream->stream_start + stream->stream_size)
            return 100;
        return (int)((pos - stream->stream_start) * 100 / stream->stream_size);
    }
    return -1;
}

size_t dcadec_stream_pack(uint8_t * out, const uint8_t * data, size_t count8, uint32_t sync)
{
    size_t i;
    if (sync == 0)
        sync = DCA_32BE(*(uint32_t*)data);
    if (sync == SYNC_WORD_CORE_14_LE)
    {
        swap16(data, count8 * 2);
        sync = SYNC_WORD_CORE_14;
    }
    if (sync == SYNC_WORD_CORE_14)
    {
        for (i = 0; i < count8; ++i)
        {
            out[0] = ((data[0] & 0x3F) << 2) | (data[1] >> 6);
            out[1] = ((data[1] & 0x3F) << 2) | ((data[2] & 0x30) >> 4);
            out[2] = ((data[2] & 0x0F) << 4) | (data[3] >> 4);
            out[3] = ((data[3] & 0x0F) << 4) | ((data[4] & 0x3C) >> 2);
            out[4] = ((data[4] & 0x03) << 6) | (data[5] >> 2);
            out[5] = ((data[5] & 0x03) << 6) | (data[6] & 0x3F);
            out[6] = data[7];
            data += 8;
            out += 7;
        }
        return count8 * 7;
    }

    return count8 * 8;
}

DCADEC_API struct dcadec_stream_info *dcadec_stream_get_info(struct dcadec_stream *stream)
{
    if (!stream || !stream->aupr_present)
        return NULL;
    struct dcadec_stream_info *info = ta_znew(NULL, struct dcadec_stream_info);
    if (!info)
        return NULL;

    info->stream_size = stream->stream_size;
    info->sample_rate = stream->aupr_sample_rate;
    info->nframes = stream->aupr_nframes;
    info->nframesamples = stream->aupr_nframesamples;
    info->npcmsamples = stream->aupr_npcmsamples;
    info->ch_mask = stream->aupr_ch_mask;
    info->ndelaysamples = stream->aupr_ndelaysamples;
    return info;
}

DCADEC_API void dcadec_stream_free_info(struct dcadec_stream_info *info)
{
    ta_free(info);
}
