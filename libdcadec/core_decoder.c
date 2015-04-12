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
#include "interpolator.h"
#include "idct.h"
#include "fixed_math.h"
#include "core_decoder.h"
#include "exss_parser.h"
#include "dmix_tables.h"

#include "core_tables.h"
#include "core_huffman.h"
#include "core_vectors.h"

enum sample_type {
    NO_BITS_ALLOCATED,
    HUFFMAN_CODE,
    BLOCK_CODE,
    NO_FURTHER_ENCODING
};

enum header_type {
    HEADER_CORE,
    HEADER_XCH,
    HEADER_XXCH
};

// Mode 0: A (mono)
// Mode 1: A + B (dual mono)
// Mode 2: L + R (stereo)
// Mode 3: (L+R) + (L-R) (sum-diff)
// Mode 4: LT + RT (left and right total)
// Mode 5: C + L + R
// Mode 6: L + R + S
// Mode 7: C + L + R + S
// Mode 8: L + R + SL + SR
// Mode 9: C + L + R + SL + SR

static const int8_t prm_ch_to_spkr_map[10][5] = {
    { SPEAKER_C,        -1,         -1,         -1,         -1 },
    { SPEAKER_L, SPEAKER_R,         -1,         -1,         -1 },
    { SPEAKER_L, SPEAKER_R,         -1,         -1,         -1 },
    { SPEAKER_L, SPEAKER_R,         -1,         -1,         -1 },
    { SPEAKER_L, SPEAKER_R,         -1,         -1,         -1 },
    { SPEAKER_C, SPEAKER_L, SPEAKER_R ,         -1,         -1 },
    { SPEAKER_L, SPEAKER_R, SPEAKER_Cs,         -1          -1 },
    { SPEAKER_C, SPEAKER_L, SPEAKER_R , SPEAKER_Cs,         -1 },
    { SPEAKER_L, SPEAKER_R, SPEAKER_Ls, SPEAKER_Rs,         -1 },
    { SPEAKER_C, SPEAKER_L, SPEAKER_R,  SPEAKER_Ls, SPEAKER_Rs }
};

static const uint8_t audio_mode_ch_mask[10] = {
    SPEAKER_MASK_C,
    SPEAKER_MASK_L | SPEAKER_MASK_R,
    SPEAKER_MASK_L | SPEAKER_MASK_R,
    SPEAKER_MASK_L | SPEAKER_MASK_R,
    SPEAKER_MASK_L | SPEAKER_MASK_R,
    SPEAKER_MASK_C | SPEAKER_MASK_L | SPEAKER_MASK_R,
    SPEAKER_MASK_L | SPEAKER_MASK_R | SPEAKER_MASK_Cs,
    SPEAKER_MASK_C | SPEAKER_MASK_L | SPEAKER_MASK_R  | SPEAKER_MASK_Cs,
    SPEAKER_MASK_L | SPEAKER_MASK_R | SPEAKER_MASK_Ls | SPEAKER_MASK_Rs,
    SPEAKER_MASK_C | SPEAKER_MASK_L | SPEAKER_MASK_R  | SPEAKER_MASK_Ls | SPEAKER_MASK_Rs
};

// 5.3.1 - Bit stream header
static int parse_frame_header(struct core_decoder *core)
{
    // Frame type
    core->normal_frame = bits_get1(&core->bits);

    // Deficit sample count
    core->deficit_samples = bits_get(&core->bits, 5) + 1;
    enforce(core->deficit_samples == 32 || core->normal_frame == false,
            "Invalid deficit sample count");

    // CRC present flag
    core->crc_present = bits_get1(&core->bits);

    // Number of PCM sample blocks
    core->npcmblocks = bits_get(&core->bits, 7) + 1;
    enforce(core->npcmblocks >= 8, "Invalid number of PCM sample blocks");

    // Primary frame byte size
    core->frame_size = bits_get(&core->bits, 14) + 1;
    enforce(core->frame_size >= 96, "Invalid frame size");

    // Audio channel arrangement
    core->audio_mode = bits_get(&core->bits, 6);
    require(core->audio_mode < 10, "Unsupported audio channel arrangement");

    // Core audio sampling frequency
    core->sample_rate = sample_rates[bits_get(&core->bits, 4)];
    enforce(core->sample_rate != 0, "Invalid core audio sampling frequency");

    // Transmission bit rate
    core->bit_rate = bit_rates[bits_get(&core->bits, 5)];
    enforce(core->bit_rate != -1, "Invalid transmission bit rate");

    // Reserved field
    bits_skip1(&core->bits);

    // Embedded dynamic range flag
    core->drc_present = bits_get1(&core->bits);

    // Embedded time stamp flag
    core->ts_present = bits_get1(&core->bits);

    // Auxiliary data flag
    core->aux_present = bits_get1(&core->bits);

    // HDCD mastering flag
    bits_skip1(&core->bits);

    // Extension audio descriptor flag
    // 0 - Channel extension (XCH)
    // 2 - Frequency extension (X96)
    // 6 - Channel extension (XXCH)
    core->ext_audio_type = bits_get(&core->bits, 3);

    // Extended coding flag
    core->ext_audio_present = bits_get1(&core->bits);

    // Audio sync word insertion flag
    core->sync_ssf = bits_get1(&core->bits);

    // Low frequency effects flag
    core->lfe_present = bits_get(&core->bits, 2);
    enforce(core->lfe_present < 3, "Invalid low frequency effects flag");

    // Predictor history flag switch
    core->predictor_history = bits_get1(&core->bits);

    // Header CRC check bytes
    if (core->crc_present)
        bits_skip(&core->bits, 16);

    // Multirate interpolator switch
    core->filter_perfect = bits_get1(&core->bits);

    // Encoder software revision
    bits_skip(&core->bits, 4);

    // Copy history
    bits_skip(&core->bits, 2);

    // Source PCM resolution
    int pcmr_index = bits_get(&core->bits, 3);
    core->source_pcm_res = sample_res[pcmr_index];
    enforce(core->source_pcm_res != 0, "Invalid source PCM resolution");
    core->es_format = !!(pcmr_index & 1);

    // Front sum/difference flag
    require(bits_get1(&core->bits) == false, "Front sum/difference not supported");

    // Surround sum/difference flag
    require(bits_get1(&core->bits) == false, "Surround sum/difference not supported");

    // Dialog normalization / unspecified
    bits_skip(&core->bits, 4);

    return 0;
}

// 5.3.2 - Primary audio coding header
static int parse_coding_header(struct core_decoder *core, enum header_type header, int xch_base)
{
    int ch, n, ret;

    size_t header_pos = core->bits.index;
    size_t header_size = 0;

    switch (header) {
    case HEADER_CORE:
        // Number of subframes
        core->nsubframes = bits_get(&core->bits, 4) + 1;

        // Number of primary audio channels
        core->nchannels = bits_get(&core->bits, 3) + 1;
        enforce(core->nchannels == audio_mode_nch[core->audio_mode],
                "Invalid number of primary audio channels");
        assert(core->nchannels <= MAX_CHANNELS - 2);

        core->ch_mask = audio_mode_ch_mask[core->audio_mode];

        core->dmix_coeffs_present = core->dmix_embedded = false;
        break;

    case HEADER_XCH:
        core->nchannels = audio_mode_nch[core->audio_mode] + 1;
        assert(core->nchannels <= MAX_CHANNELS - 1);
        core->ch_mask |= SPEAKER_MASK_Cs;
        break;

    case HEADER_XXCH:
        // Channel set header length
        header_size = bits_get(&core->bits, 7) + 1;

        // Check CRC
        if (core->xxch_crc_present)
            if ((ret = bits_check_crc(&core->bits, header_pos, header_pos + header_size * 8)) < 0)
                return ret;

        // Number of channels in a channel set
        n = bits_get(&core->bits, 3) + 1;
        require(n < 3, "Too many XXCH audio channels");
        core->nchannels = audio_mode_nch[core->audio_mode] + n;
        assert(core->nchannels <= MAX_CHANNELS);

        // Loudspeaker activity mask
        core->ch_mask |= bits_get(&core->bits, core->xxch_mask_nbits - 6) << 6;

        // Downmix coefficients present in stream
        core->dmix_coeffs_present = bits_get1(&core->bits);

        if (core->dmix_coeffs_present) {
            // Downmix already performed by encoder
            core->dmix_embedded = bits_get1(&core->bits);

            // Downmix scale factor
            int code = bits_get(&core->bits, 6);
            if (code) {
                unsigned int index = code * 4 - 44;
                enforce(index < dca_countof(dmix_table_inv),
                        "Invalid downmix scale index");
                core->dmix_scale_inv = dmix_table_inv[index];
            } else {
                core->dmix_scale_inv = 0;
            }

            // Downmix channel mapping mask
            for (ch = xch_base; ch < core->nchannels; ch++)
                core->dmix_mask[ch] = bits_get(&core->bits, core->xxch_mask_nbits);

            // Downmix coefficients
            int *coeff_ptr = core->dmix_coeff;
            for (ch = xch_base; ch < core->nchannels; ch++) {
                for (n = 0; n < core->xxch_mask_nbits; n++) {
                    if (core->dmix_mask[ch] & (1 << n)) {
                        int code = bits_get(&core->bits, 7);
                        int sign = (code >> 6) - 1; code &= 63;
                        if (code) {
                            unsigned int index = code * 4 - 4;
                            enforce(index < dca_countof(dmix_table),
                                    "Invalid downmix coefficient index");
                            *coeff_ptr++ = (dmix_table[index] ^ sign) - sign;
                        } else {
                            *coeff_ptr++ = 0;
                        }
                    }
                }
            }
        } else {
            core->dmix_embedded = false;
        }

        break;
    }

    // Subband activity count
    for (ch = xch_base; ch < core->nchannels; ch++)
        core->nsubbands[ch] = bits_get(&core->bits, 5) + 2;

    // High frequency VQ start subband
    for (ch = xch_base; ch < core->nchannels; ch++)
        core->subband_vq_start[ch] = bits_get(&core->bits, 5) + 1;

    // Joint intensity coding index
    for (ch = xch_base; ch < core->nchannels; ch++)
        core->joint_intensity_index[ch] = bits_get(&core->bits, 3);

    // Transient mode code book
    for (ch = xch_base; ch < core->nchannels; ch++)
        core->transition_mode_sel[ch] = bits_get(&core->bits, 2);

    // Scale factor code book
    for (ch = xch_base; ch < core->nchannels; ch++) {
        core->scale_factor_sel[ch] = bits_get(&core->bits, 3);
        enforce(core->scale_factor_sel[ch] < 7, "Invalid scale factor code book");
    }

    // Bit allocation quantizer select
    for (ch = xch_base; ch < core->nchannels; ch++) {
        core->bit_allocation_sel[ch] = bits_get(&core->bits, 3);
        enforce(core->bit_allocation_sel[ch] < 7, "Invalid bit allocation quantizer select");
    }

    // Quantization index codebook select
    for (n = 0; n < NUM_CODE_BOOKS; n++)
        for (ch = xch_base; ch < core->nchannels; ch++)
            core->quant_index_sel[ch][n] = bits_get(&core->bits, quant_index_sel_nbits[n]);

    // Scale factor adjustment index
    for (n = 0; n < NUM_CODE_BOOKS; n++)
        for (ch = xch_base; ch < core->nchannels; ch++)
            if (core->quant_index_sel[ch][n] < quant_index_group_size[n])
                core->scale_factor_adj[ch][n] = scale_factor_adj[bits_get(&core->bits, 2)];

    if (header == HEADER_XXCH) {
        // Reserved
        // Byte align
        // CRC16 of channel set header
        if ((ret = bits_seek(&core->bits, header_pos + header_size * 8)) < 0)
            return ret;
    } else {
        // Audio header CRC check word
        if (core->crc_present)
            bits_skip(&core->bits, 16);
    }

    return 0;
}

static int parse_scale(struct core_decoder *core, int *scale_index, int sel)
{
    // Select the root square table
    const int32_t *scale_table;
    size_t scale_size;
    if (sel > 5) {
        scale_table = scale_factors_7bit;
        scale_size = dca_countof(scale_factors_7bit);
    } else {
        scale_table = scale_factors_6bit;
        scale_size = dca_countof(scale_factors_6bit);
    }

    if (sel < 5)
        // If Huffman code was used, the difference of scales was encoded
        *scale_index += bits_get_signed_vlc(&core->bits, &scale_factor_huff[sel]);
    else
        *scale_index = bits_get(&core->bits, sel + 1);

    // Look up scale factor from the root square table
    enforce((unsigned int)*scale_index < scale_size, "Invalid scale factor index");
    return scale_table[*scale_index];
}

static int parse_joint_scale(struct core_decoder *core, int sel)
{
    int scale_index;

    if (sel < 5)
        scale_index = bits_get_signed_vlc(&core->bits, &scale_factor_huff[sel]);
    else
        scale_index = bits_get(&core->bits, sel + 1);

    // Bias by 64
    scale_index += 64;

    enforce((unsigned int)scale_index < dca_countof(joint_scale_factors), "Invalid joint scale factor index");
    return joint_scale_factors[scale_index];
}

// 5.4.1 - Primary audio coding side information
static int parse_subframe_header(struct core_decoder *core, int sf,
                                 enum header_type header, int xch_base)
{
    int ch, band, ret;

    if (header == HEADER_CORE) {
        // Subsubframe count
        core->nsubsubframes[sf] = bits_get(&core->bits, 2) + 1;

        // Partial subsubframe sample count
        bits_skip(&core->bits, 3);
    }

    // Prediction mode
    for (ch = xch_base; ch < core->nchannels; ch++)
        for (band = 0; band < core->nsubbands[ch]; band++)
            core->prediction_mode[ch][band] = bits_get1(&core->bits);

    // Prediction coefficients VQ address
    for (ch = xch_base; ch < core->nchannels; ch++)
        for (band = 0; band < core->nsubbands[ch]; band++)
            if (core->prediction_mode[ch][band])
                core->prediction_vq_index[ch][band] = bits_get(&core->bits, 12);

    // Bit allocation index
    for (ch = xch_base; ch < core->nchannels; ch++) {
        // Not high frequency VQ subbands
        for (band = 0; band < core->subband_vq_start[ch]; band++) {
            // Select codebook
            int abits, sel = core->bit_allocation_sel[ch];
            if (sel < 5)
                abits = bits_get_unsigned_vlc(&core->bits, &bit_allocation_huff[sel]) + 1;
            else
                abits = bits_get(&core->bits, sel - 1);
            enforce(abits < 27, "Invalid bit allocation index");
            core->bit_allocation[ch][band] = abits;
        }
    }

    // Transition mode
    for (ch = xch_base; ch < core->nchannels; ch++) {
        // Clear transition mode for all subbands
        for (band = 0; band < core->nsubbands[ch]; band++)
            core->transition_mode[sf][ch][band] = 0;

        // Transient possible only if more than one subsubframe
        if (core->nsubsubframes[sf] > 1) {
            // Not high frequency VQ subbands
            for (band = 0; band < core->subband_vq_start[ch]; band++) {
                // Present only if bits allocated
                if (core->bit_allocation[ch][band]) {
                    int sel = core->transition_mode_sel[ch];
                    const struct huffman *huff = &transition_mode_huff[sel];
                    int trans_ssf = bits_get_unsigned_vlc(&core->bits, huff);
                    enforce(trans_ssf < 4, "Invalid transition mode index");
                    core->transition_mode[sf][ch][band] = trans_ssf;
                }
            }
        }
    }

    // Scale factors
    for (ch = xch_base; ch < core->nchannels; ch++) {
        // Clear scale factors
        for (band = 0; band < core->nsubbands[ch]; band++) {
            core->scale_factors[ch][band][0] = 0;
            core->scale_factors[ch][band][1] = 0;
        }

        // Select codebook
        int sel = core->scale_factor_sel[ch];

        // Clear accumulation
        int scale_index = 0;

        // Extract scales for subbands up to VQ
        for (band = 0; band < core->subband_vq_start[ch]; band++) {
            if (core->bit_allocation[ch][band]) {
                if ((ret = parse_scale(core, &scale_index, sel)) < 0)
                    return ret;
                core->scale_factors[ch][band][0] = ret;
                if (core->transition_mode[sf][ch][band]) {
                    if ((ret = parse_scale(core, &scale_index, sel)) < 0)
                        return ret;
                    core->scale_factors[ch][band][1] = ret;
                }
            }
        }

        // High frequency VQ subbands
        for (band = core->subband_vq_start[ch]; band < core->nsubbands[ch]; band++) {
            if ((ret = parse_scale(core, &scale_index, sel)) < 0)
                return ret;
            core->scale_factors[ch][band][0] = ret;
        }
    }

    // Joint subband codebook select
    for (ch = xch_base; ch < core->nchannels; ch++) {
        // Only if joint subband coding is enabled
        if (core->joint_intensity_index[ch]) {
            core->joint_scale_sel[ch] = bits_get(&core->bits, 3);
            enforce(core->joint_scale_sel[ch] < 7, "Invalid joint scale factor code book");
        }
    }

    // Scale factors for joint subband coding
    for (ch = xch_base; ch < core->nchannels; ch++) {
        // Only if joint subband coding is enabled
        if (core->joint_intensity_index[ch]) {
            // Select codebook
            int sel = core->joint_scale_sel[ch];
            // Get source channel
            int src_ch = core->joint_intensity_index[ch] - 1;
            for (band = core->nsubbands[ch]; band < core->nsubbands[src_ch]; band++) {
                if ((ret = parse_joint_scale(core, sel)) < 0)
                    return ret;
                core->joint_scale_factors[ch][band] = ret;
            }
        }
    }

    // Dynamic range coefficient
    if (core->drc_present && header == HEADER_CORE)
        bits_skip(&core->bits, 8);

    // Side information CRC check word
    if (core->crc_present)
        bits_skip(&core->bits, 16);

    return 0;
}

static int parse_block_code(struct core_decoder *core, int *value, int sel)
{
    // Select block code book
    // Extract the block code index from the bit stream
    int code = bits_get(&core->bits, block_code_nbits[sel]);
    int levels = quant_levels[sel];
    int offset = (levels - 1) >> 1;

    // Look up 4 samples from the block code book
    for (int n = 0; n < 4; n++) {
        value[n] = (code % levels) - offset;
        code /= levels;
    }

    enforce(code == 0, "Failed to decode block code");
    return 0;
}

static inline void dequantize(int *output, const int *input, int step_size,
                              int scale, bool residual)
{
    // Account for quantizer step size
    int64_t step_scale = (int64_t)step_size * scale;
    int nbits = 64 - dca_clz64(step_scale | INT64_C(1));
    int shift = nbits > 23 ? nbits - 23 : 0;
    int32_t _step_scale = (int32_t)(step_scale >> shift);

    // Scale the samples
    if (residual) {
        for (int n = 0; n < NUM_SUBBAND_SAMPLES; n++)
            output[n] += clip23(mul__(input[n], _step_scale, 22 - shift));
    } else {
        for (int n = 0; n < NUM_SUBBAND_SAMPLES; n++)
            output[n] = clip23(mul__(input[n], _step_scale, 22 - shift));
    }
}

static inline int extract_audio(struct core_decoder *core, int *audio,
                                int abits, int *quant_index_sel)
{
    const struct huffman *huff = NULL;

    // Assume no further encoding by default
    enum sample_type type = NO_FURTHER_ENCODING;

    assert(abits >= 0 && abits < 27);

    // Select the quantizer
    if (abits == 0) {
        // No bits allocated
        type = NO_BITS_ALLOCATED;
    } else if (abits <= NUM_CODE_BOOKS) {
        // Select the group of code books
        const struct huffman *group_huff = quant_index_group_huff[abits - 1];
        int group_size = quant_index_group_size[abits - 1];
        // Select quantization index code book
        int sel = quant_index_sel[abits - 1];
        if (sel < group_size) {
            type = HUFFMAN_CODE;
            huff = &group_huff[sel];
        } else if (abits <= 7) {
            type = BLOCK_CODE;
        }
    }

    // Extract bits from the bit stream
    int ret;
    switch (type) {
    case NO_BITS_ALLOCATED:
        memset(audio, 0, NUM_SUBBAND_SAMPLES * sizeof(*audio));
        break;
    case HUFFMAN_CODE:
        if ((ret = bits_get_signed_vlc_array(&core->bits, audio, NUM_SUBBAND_SAMPLES, huff)) < 0)
            return ret;
        break;
    case BLOCK_CODE:
        if ((ret = parse_block_code(core, audio + 0, abits)) < 0)
            return ret;
        if ((ret = parse_block_code(core, audio + 4, abits)) < 0)
            return ret;
        break;
    case NO_FURTHER_ENCODING:
        bits_get_signed_array(&core->bits, audio, NUM_SUBBAND_SAMPLES, abits - 3);
        break;
    }

    return type;
}

// 5.5 - Primary audio data arrays
static int parse_subband_samples(struct core_decoder *core, int sf, int ssf,
                                 int ch, int band, int sub_pos)
{
    int abits = core->bit_allocation[ch][band];
    int audio[NUM_SUBBAND_SAMPLES];
    int ret, step_size, trans_ssf, scale;

    if ((ret = extract_audio(core, audio, abits, core->quant_index_sel[ch])) < 0)
        return ret;

    // Select quantization step size table
    // Look up quantization step size
    if (core->bit_rate == -2)
        step_size = step_size_lossless[abits];
    else
        step_size = step_size_lossy[abits];

    // Identify transient location
    trans_ssf = core->transition_mode[sf][ch][band];

    // Determine proper scale factor
    if (trans_ssf == 0 || ssf < trans_ssf)
        scale = core->scale_factors[ch][band][0];
    else
        scale = core->scale_factors[ch][band][1];

    // Adjustment of scale factor
    // Only when SEL indicates Huffman code
    if (ret == HUFFMAN_CODE)
        scale = clip23(mul22nrd(core->scale_factor_adj[ch][abits - 1], scale));

    dequantize(core->subband_samples[ch][band] +
               sub_pos + ssf * NUM_SUBBAND_SAMPLES,
               audio, step_size, scale, false);
    return 0;
}

// 5.5 - Primary audio data arrays
static int parse_subframe_audio(struct core_decoder *core, int sf, enum header_type header,
                                int xch_base, int *sub_pos, int *lfe_pos)
{
    int ssf, ch, band;

    // Number of subband samples in this subframe
    int nsamples = core->nsubsubframes[sf] * NUM_SUBBAND_SAMPLES;
    enforce(*sub_pos + nsamples <= core->npcmblocks, "Subband sample buffer overflow");

    // VQ encoded subbands
    for (ch = xch_base; ch < core->nchannels; ch++) {
        for (band = core->subband_vq_start[ch]; band < core->nsubbands[ch]; band++) {
            // Extract the VQ address from the bit stream
            int vq_index = bits_get(&core->bits, 10);

            // Get the scale factor
            int scale = core->scale_factors[ch][band][0];

            // Look up the VQ code book for 32 subband samples
            const int8_t *vq_samples = high_freq_samples[vq_index];

            // Scale and take the samples
            int *samples = core->subband_samples[ch][band] + *sub_pos;
            for (int n = 0; n < nsamples; n++)
                samples[n] = clip23(mul4(scale, vq_samples[n]));
        }
    }

    // Low frequency effect data
    if (core->lfe_present && header == HEADER_CORE) {
        // Number of LFE samples in this subframe
        int nlfesamples = 2 * core->lfe_present * core->nsubsubframes[sf];
        assert(nlfesamples <= MAX_LFE_SAMPLES);

        // Extract LFE samples from the bit stream
        int audio[MAX_LFE_SAMPLES];
        bits_get_signed_array(&core->bits, audio, nlfesamples, 8);

        // Extract scale factor index from the bit stream
        unsigned int scale_index = bits_get(&core->bits, 8);
        enforce(scale_index < dca_countof(scale_factors_7bit),
                "Invalid LFE scale factor index");

        // Look up the 7-bit root square quantization table
        int scale = scale_factors_7bit[scale_index];

        // Account for quantizer step size which is 0.035
        int step_scale = mul23(4697620, scale);

        // Scale the LFE samples
        int *samples = core->lfe_samples + *lfe_pos;
        for (int n = 0; n < nlfesamples; n++)
            samples[n] = clip23((audio[n] * step_scale) >> 4);

        // Advance LFE sample pointer for the next subframe
        *lfe_pos += nlfesamples;
    }

    // Audio data
    for (ssf = 0; ssf < core->nsubsubframes[sf]; ssf++) {
        int ret;

        for (ch = xch_base; ch < core->nchannels; ch++)
            // Not high frequency VQ subbands
            for (band = 0; band < core->subband_vq_start[ch]; band++)
                if ((ret = parse_subband_samples(core, sf, ssf, ch, band, *sub_pos)) < 0)
                    return ret;

        // DSYNC
        if (ssf == core->nsubsubframes[sf] - 1 || core->sync_ssf)
            enforce(bits_get(&core->bits, 16) == 0xffff, "DSYNC check failed");
    }

    // Inverse ADPCM
    for (ch = xch_base; ch < core->nchannels; ch++) {
        for (band = 0; band < core->nsubbands[ch]; band++) {
            // Only if prediction mode is on
            if (core->prediction_mode[ch][band]) {
                int *samples = core->subband_samples[ch][band] + *sub_pos;

                // Extract the VQ index
                int vq_index = core->prediction_vq_index[ch][band];

                // Look up the VQ table for prediction coefficients
                const int16_t *vq_coeffs = adpcm_coeffs[vq_index];
                for (int m = 0; m < nsamples; m++) {
                    int64_t err = INT64_C(0);
                    for (int n = 0; n < NUM_ADPCM_COEFFS; n++)
                        err += (int64_t)samples[m - n - 1] * vq_coeffs[n];
                    samples[m] = clip23(samples[m] + clip23(norm13(err)));
                }
            }
        }
    }

    // Joint subband coding
    for (ch = xch_base; ch < core->nchannels; ch++) {
        // Only if joint subband coding is enabled
        if (core->joint_intensity_index[ch]) {
            // Get source channel
            int src_ch = core->joint_intensity_index[ch] - 1;
            for (band = core->nsubbands[ch]; band < core->nsubbands[src_ch]; band++) {
                int *src = core->subband_samples[src_ch][band] + *sub_pos;
                int *dst = core->subband_samples[    ch][band] + *sub_pos;
                int scale = core->joint_scale_factors[ch][band];
                for (int n = 0; n < nsamples; n++)
                    dst[n] = clip23(mul17(src[n], scale));
            }
        }
    }

    // Advance subband sample pointer for the next subframe
    *sub_pos += nsamples;
    return 0;
}

static void erase_adpcm_history(struct core_decoder *core)
{
    // Erase ADPCM history from previous frame if
    // predictor history switch was disabled
    for (int ch = 0; ch < MAX_CHANNELS; ch++) {
        for (int band = 0; band < MAX_SUBBANDS; band++) {
            int *samples = core->subband_samples[ch][band] - NUM_ADPCM_COEFFS;
            for (int n = 0; n < NUM_ADPCM_COEFFS; n++)
                samples[n] = 0;
        }
    }
}

static int alloc_sample_buffer(struct core_decoder *core)
{
    int nchsamples = NUM_ADPCM_COEFFS + core->npcmblocks;
    int nframesamples = nchsamples * MAX_CHANNELS * MAX_SUBBANDS;
    int nlfesamples = MAX_LFE_HISTORY + core->npcmblocks / 2;

    // Reallocate subband sample buffer
    int ret;
    if ((ret = dca_realloc(core, &core->subband_buffer, nframesamples + nlfesamples, sizeof(int))) < 0)
        return ret;
    if (ret > 0) {
        for (int ch = 0; ch < MAX_CHANNELS; ch++)
            for (int band = 0; band < MAX_SUBBANDS; band++)
                core->subband_samples[ch][band] = core->subband_buffer +
                    (ch * MAX_SUBBANDS + band) * nchsamples + NUM_ADPCM_COEFFS;
        core->lfe_samples = core->subband_buffer + nframesamples;
    }

    if (!core->predictor_history)
        erase_adpcm_history(core);

    return 0;
}

static int parse_frame_data(struct core_decoder *core, enum header_type header, int xch_base)
{
    int ret;
    if ((ret = parse_coding_header(core, header, xch_base)) < 0)
        return ret;

    int sub_pos = 0;
    int lfe_pos = MAX_LFE_HISTORY;
    for (int sf = 0; sf < core->nsubframes; sf++) {
        if ((ret = parse_subframe_header(core, sf, header, xch_base)) < 0)
            return ret;
        if ((ret = parse_subframe_audio(core, sf, header, xch_base, &sub_pos, &lfe_pos)) < 0)
            return ret;
    }

    for (int ch = xch_base; ch < core->nchannels; ch++) {
        // Number of active subbands for this channel
        int nsubbands;
        if (core->joint_intensity_index[ch]) {
            nsubbands = core->nsubbands[core->joint_intensity_index[ch] - 1];
            if (nsubbands < core->nsubbands[ch])
                nsubbands = core->nsubbands[ch];
        } else {
            nsubbands = core->nsubbands[ch];
        }

        // Update history for ADPCM
        for (int band = 0; band < nsubbands; band++) {
            int *samples = core->subband_samples[ch][band] - NUM_ADPCM_COEFFS;
            for (int n = NUM_ADPCM_COEFFS - 1; n >= 0; n--)
                samples[n] = samples[core->npcmblocks + n];
        }

        // Clear inactive subbands
        for (int band = nsubbands; band < MAX_SUBBANDS; band++) {
            int *samples = core->subband_samples[ch][band] - NUM_ADPCM_COEFFS;
            memset(samples, 0, (NUM_ADPCM_COEFFS + core->npcmblocks) * sizeof(int));
        }
    }

    return 0;
}

static int map_prm_ch_to_spkr(struct core_decoder *core, int ch)
{
    int pos = audio_mode_nch[core->audio_mode];
    if (ch < pos)
        return prm_ch_to_spkr_map[core->audio_mode][ch];

    for (int spkr = SPEAKER_Cs; spkr < SPEAKER_COUNT; spkr++)
        if (core->ch_mask & (1 << spkr))
            if (pos++ == ch)
                return spkr;

    return -1;
}

static int map_spkr_to_core_spkr(struct core_decoder *core, int spkr)
{
    if (core->ch_mask & (1 << spkr))
        return spkr;
    if (spkr == SPEAKER_Lss && (core->ch_mask & SPEAKER_MASK_Ls))
        return SPEAKER_Ls;
    if (spkr == SPEAKER_Rss && (core->ch_mask & SPEAKER_MASK_Rs))
        return SPEAKER_Rs;
    return -1;
}

int core_filter(struct core_decoder *core, int flags)
{
    struct x96_decoder *x96 = NULL;

    // Externally set CORE_SYNTH_X96 flags implies that X96 synthesis should be
    // enabled, yet actual X96 subband data should be discarded. This is a special
    // case for lossless residual decoder that apparently ignores X96 data.
    if (!(flags & DCADEC_FLAG_CORE_SYNTH_X96) && core->x96_present) {
        x96 = core->x96_decoder;
        if (x96)
            flags |= DCADEC_FLAG_CORE_SYNTH_X96;
    }

    // X96 synthesis enabled flag
    bool synth_x96 = !!(flags & DCADEC_FLAG_CORE_SYNTH_X96);

    // Output sample rate
    core->output_rate = core->sample_rate << synth_x96;

    // Number of PCM samples in this frame
    core->npcmsamples = (core->npcmblocks * NUM_PCMBLOCK_SAMPLES) << synth_x96;

    // Add LFE channel if present
    if (core->lfe_present)
        core->ch_mask |= SPEAKER_MASK_LFE1;

    // Reallocate PCM output buffer
    int ret;
    if ((ret = dca_realloc(core, &core->output_buffer, core->npcmsamples * dca_popcount(core->ch_mask), sizeof(int))) < 0)
        return ret;

    int *ptr = core->output_buffer;
    for (int spkr = 0; spkr < SPEAKER_COUNT; spkr++) {
        if (core->ch_mask & (1 << spkr)) {
            core->output_samples[spkr] = ptr;
            ptr += core->npcmsamples;
        } else {
            core->output_samples[spkr] = NULL;
        }
    }

    // Handle change of certain filtering parameters
    int diff = core->filter_flags ^ flags;

    if (diff & (DCADEC_FLAG_CORE_BIT_EXACT | DCADEC_FLAG_CORE_SYNTH_X96)) {
        for (int ch = 0; ch < MAX_CHANNELS; ch++) {
            ta_free(core->subband_dsp[ch]);
            core->subband_dsp[ch] = NULL;
        }
    }

    if (diff & (DCADEC_FLAG_CORE_BIT_EXACT | DCADEC_FLAG_CORE_LFE_FIR))
        memset(core->lfe_samples, 0, MAX_LFE_HISTORY * sizeof(int));

    if (diff & DCADEC_FLAG_CORE_SYNTH_X96)
        core->output_history_lfe = 0;

    core->filter_flags = flags;

    if (!core->subband_dsp_idct)
        if (!(core->subband_dsp_idct = idct_init(core)))
            return -DCADEC_ENOMEM;

    // Filter primary channels
    for (int ch = 0; ch < core->nchannels; ch++) {
        // Allocate subband DSP
        if (!core->subband_dsp[ch])
            if (!(core->subband_dsp[ch] = interpolator_create(core->subband_dsp_idct, flags)))
                return -DCADEC_ENOMEM;

        // Map this primary channel to speaker
        int spkr = map_prm_ch_to_spkr(core, ch);
        if (spkr < 0)
            return -DCADEC_EINVAL;

        // Get the pointer to high frequency subbands for this channel, if present
        int **subband_samples_hi;
        if (x96 && ch < x96->nchannels)
            subband_samples_hi = x96->subband_samples[ch];
        else
            subband_samples_hi = NULL;

        // Filter bank reconstruction
        core->subband_dsp[ch]->interpolate(core->subband_dsp[ch],
                                           core->output_samples[spkr],
                                           core->subband_samples[ch],
                                           subband_samples_hi,
                                           core->npcmblocks,
                                           core->filter_perfect);
    }

    // Filter LFE channel
    if (core->lfe_present) {
        // Select LFE DSP
        interpolate_lfe_t interpolate;
        if (flags & DCADEC_FLAG_CORE_BIT_EXACT)
            interpolate = interpolate_lfe_fixed_fir;
        else if (flags & DCADEC_FLAG_CORE_LFE_FIR)
            interpolate = interpolate_lfe_float_fir;
        else
            interpolate = interpolate_lfe_float_iir;

        // Interpolation of LFE channel
        interpolate(core->output_samples[SPEAKER_LFE1],
                    core->lfe_samples,
                    core->npcmblocks >> (3 - core->lfe_present),
                    core->lfe_present == 1,
                    synth_x96);

        if (flags & DCADEC_FLAG_CORE_SYNTH_X96) {
            // Filter 96 kHz oversampled LFE PCM to attenuate high frequency
            // (47.6 - 48.0 kHz) components of interpolation image
            int history = core->output_history_lfe;
            int *samples = core->output_samples[SPEAKER_LFE1];
            int nsamples = core->npcmsamples;
            for (int n = 0; n < nsamples; n += 2) {
                int64_t res1 = INT64_C(2097471) * samples[n] + INT64_C(6291137) * history;
                int64_t res2 = INT64_C(6291137) * samples[n] + INT64_C(2097471) * history;
                history = samples[n];
                samples[n    ] = clip23(norm23(res1));
                samples[n + 1] = clip23(norm23(res2));
            }

            // Update LFE PCM history
            core->output_history_lfe = history;
        }
    }

    if (!(flags & DCADEC_FLAG_KEEP_DMIX_MASK)) {
        int nsamples = core->npcmsamples;

        // Undo embedded XCH downmix
        if (core->es_format && core->xch_present && core->audio_mode >= 8) {
            int *samples_ls = core->output_samples[SPEAKER_Ls];
            int *samples_rs = core->output_samples[SPEAKER_Rs];
            int *samples_cs = core->output_samples[SPEAKER_Cs];
            for (int n = 0; n < nsamples; n++) {
                int cs = mul23(samples_cs[n], 5931520);
                samples_ls[n] = clip23(samples_ls[n] - cs);
                samples_rs[n] = clip23(samples_rs[n] - cs);
            }
        }

        // Undo embedded XXCH downmix
        if (core->dmix_embedded) {
            // Undo embedded core downmix pre-scaling
            int scale_inv = core->dmix_scale_inv;
            if (scale_inv != (1 << 16)) {
                for (int spkr = 0; spkr < SPEAKER_Cs; spkr++) {
                    if ((core->ch_mask & (1 << spkr))) {
                        int *samples = core->output_samples[spkr];
                        for (int n = 0; n < nsamples; n++)
                            samples[n] = mul16(samples[n], scale_inv);
                    }
                }
            }

            // Undo downmix
            int *coeff_ptr = core->dmix_coeff;
            for (int ch = audio_mode_nch[core->audio_mode]; ch < core->nchannels; ch++) {
                int spkr1 = map_prm_ch_to_spkr(core, ch);
                if (spkr1 < 0)
                    return -DCADEC_EINVAL;
                for (int spkr2 = 0; spkr2 < core->xxch_mask_nbits; spkr2++) {
                    if (core->dmix_mask[ch] & (1 << spkr2)) {
                        int spkr3 = map_spkr_to_core_spkr(core, spkr2);
                        if (spkr3 < 0)
                            return -DCADEC_EINVAL;
                        int coeff = mul16(*coeff_ptr++, scale_inv);
                        if (coeff) {
                            int *src = core->output_samples[spkr1];
                            int *dst = core->output_samples[spkr3];
                            for (int n = 0; n < nsamples; n++)
                                dst[n] -= mul15(src[n], coeff);
                        }
                    }
                }
            }

            // Clip core channels
            for (int spkr = 0; spkr < SPEAKER_Cs; spkr++) {
                if (core->ch_mask & (1 << spkr)) {
                    int *samples = core->output_samples[spkr];
                    for (int n = 0; n < nsamples; n++)
                        samples[n] = clip23(samples[n]);
                }
            }
        }
    }

    // Reduce core bit width
    if (flags & DCADEC_FLAG_CORE_SOURCE_PCM_RES) {
        int shift = 24 - core->source_pcm_res;
        if (shift > 0) {
            int round = 1 << (shift - 1);
            int nsamples = core->npcmsamples;
            for (int spkr = 0; spkr < SPEAKER_COUNT; spkr++) {
                if (core->ch_mask & (1 << spkr)) {
                    int *samples = core->output_samples[spkr];
                    for (int n = 0; n < nsamples; n++)
                        samples[n] = (samples[n] + round) >> shift;
                }
            }
        }
        core->bits_per_sample = core->source_pcm_res;
    } else {
        core->bits_per_sample = 24;
    }

    return 0;
}

static int parse_xch_frame(struct core_decoder *core)
{
    enforce(!(core->ch_mask & SPEAKER_MASK_Cs), "XCH with Cs speaker already present");

    int ret;
    if ((ret = parse_frame_data(core, HEADER_XCH, core->nchannels)) < 0)
        return ret;

    // Seek to the end of core frame, don't trust XCH frame size
    return bits_seek(&core->bits, core->frame_size * 8);
}

static int parse_xxch_frame(struct core_decoder *core)
{
    enforce(!core->xch_present, "XXCH with XCH already present");

    size_t header_pos = core->bits.index;

    // XXCH frame header length
    size_t header_size = bits_get(&core->bits, 6) + 1;
    enforce(header_size > 4, "Invalid XXCH header size");

    size_t header_end = header_pos + header_size * 8 - 32;

    // Check XXCH frame header CRC
    int ret;
    if ((ret = bits_check_crc(&core->bits, header_pos, header_end)) < 0)
        return ret;

    // CRC presence flag for channel set header
    core->xxch_crc_present = bits_get1(&core->bits);

    // Number of bits for loudspeaker mask
    core->xxch_mask_nbits = bits_get(&core->bits, 5) + 1;
    enforce(core->xxch_mask_nbits > 6, "Invalid number of bits for XXCH speaker mask");

    // Number of channel sets
    int xxch_nchsets = bits_get(&core->bits, 2) + 1;
    require(xxch_nchsets == 1, "Unsupported number of XXCH channel sets");

    // Channel set 0 data byte size
    int xxch_frame_size = bits_get(&core->bits, 14) + 1;

    // Core loudspeaker activity mask
    core->xxch_core_mask = bits_get(&core->bits, core->xxch_mask_nbits);

    // Reserved
    // Byte align
    // CRC16 of XXCH frame header
    if ((ret = bits_seek(&core->bits, header_end)) < 0)
        return ret;

    // Parse XXCH channel set 0
    if ((ret = parse_frame_data(core, HEADER_XXCH, core->nchannels)) < 0)
        return ret;

    return bits_seek(&core->bits, header_end + xxch_frame_size * 8);
}

static int parse_xbr_subframe(struct core_decoder *core, int xbr_base_ch, int xbr_nchannels,
                              int *xbr_nsubbands, bool xbr_transition_mode, int sf, int *sub_pos)
{
    int     xbr_nabits[MAX_CHANNELS];
    int     xbr_bit_allocation[MAX_CHANNELS][MAX_SUBBANDS];
    int     xbr_scale_nbits[MAX_CHANNELS];
    int     xbr_scale_factors[MAX_CHANNELS][MAX_SUBBANDS][2];
    int     ch, band, ssf;

    // Number of subband samples in this subframe
    int nsamples = core->nsubsubframes[sf] * NUM_SUBBAND_SAMPLES;
    enforce(*sub_pos + nsamples <= core->npcmblocks, "Subband sample buffer overflow");

    // Number of bits for XBR bit allocation index
    for (ch = xbr_base_ch; ch < xbr_nchannels; ch++)
        xbr_nabits[ch] = bits_get(&core->bits, 2) + 2;

    // XBR bit allocation index
    for (ch = xbr_base_ch; ch < xbr_nchannels; ch++)
        for (band = 0; band < xbr_nsubbands[ch]; band++)
            xbr_bit_allocation[ch][band] = bits_get(&core->bits, xbr_nabits[ch]);

    // Number of bits for scale indices
    for (ch = xbr_base_ch; ch < xbr_nchannels; ch++) {
        xbr_scale_nbits[ch] = bits_get(&core->bits, 3);
        enforce(xbr_scale_nbits[ch] > 0, "Invalid number of bits for XBR scale factor index");
    }

    // XBR scale factors
    for (ch = xbr_base_ch; ch < xbr_nchannels; ch++) {
        // Select the root square table
        const int32_t *scale_table;
        size_t scale_size;
        if (core->scale_factor_sel[ch] > 5) {
            scale_table = scale_factors_7bit;
            scale_size = dca_countof(scale_factors_7bit);
        } else {
            scale_table = scale_factors_6bit;
            scale_size = dca_countof(scale_factors_6bit);
        }

        // Parse scale factor indices
        // Look up scale factors from the root square table
        for (band = 0; band < xbr_nsubbands[ch]; band++) {
            if (xbr_bit_allocation[ch][band] > 0) {
                unsigned int scale_index = bits_get(&core->bits, xbr_scale_nbits[ch]);
                enforce(scale_index < scale_size, "Invalid XBR scale factor index");
                xbr_scale_factors[ch][band][0] = scale_table[scale_index];
                if (xbr_transition_mode && core->transition_mode[sf][ch][band]) {
                    scale_index = bits_get(&core->bits, xbr_scale_nbits[ch]);
                    enforce(scale_index < scale_size, "Invalid XBR scale factor index");
                    xbr_scale_factors[ch][band][1] = scale_table[scale_index];
                }
            }
        }
    }

    // Audio data
    for (ssf = 0; ssf < core->nsubsubframes[sf]; ssf++) {
        for (ch = xbr_base_ch; ch < xbr_nchannels; ch++) {
            for (band = 0; band < xbr_nsubbands[ch]; band++) {
                int audio[NUM_SUBBAND_SAMPLES];

                // Select the quantizer
                int abits = xbr_bit_allocation[ch][band];
                if (abits > 7) {
                    // No further encoding
                    bits_get_signed_array(&core->bits, audio, NUM_SUBBAND_SAMPLES, abits - 3);
                } else if (abits > 0) {
                    // Block codes
                    int ret;
                    if ((ret = parse_block_code(core, audio + 0, abits)) < 0)
                        return ret;
                    if ((ret = parse_block_code(core, audio + 4, abits)) < 0)
                        return ret;
                } else {
                    // No bits allocated
                    continue;
                }

                int step_size, trans_ssf, scale;

                // Look up quantization step size
                step_size = step_size_lossless[abits];

                // Identify transient location
                if (xbr_transition_mode)
                    trans_ssf = core->transition_mode[sf][ch][band];
                else
                    trans_ssf = 0;

                // Determine proper scale factor
                if (trans_ssf == 0 || ssf < trans_ssf)
                    scale = xbr_scale_factors[ch][band][0];
                else
                    scale = xbr_scale_factors[ch][band][1];

                dequantize(core->subband_samples[ch][band] +
                           *sub_pos + ssf * NUM_SUBBAND_SAMPLES,
                           audio, step_size, scale, true);
            }
        }

        // DSYNC
        if (ssf == core->nsubsubframes[sf] - 1 || core->sync_ssf)
            enforce(bits_get(&core->bits, 16) == 0xffff, "DSYNC check failed");
    }

    // Advance subband sample pointer for the next subframe
    *sub_pos += nsamples;
    return 0;
}

static int parse_xbr_frame(struct core_decoder *core, int flags)
{
    int     xbr_frame_size[4];
    int     xbr_nchannels[4];
    int     xbr_nsubbands[4 * 8];

    size_t header_pos = core->bits.index;

    // XBR frame header length
    size_t header_size = bits_get(&core->bits, 6) + 1;
    enforce(header_size > 4, "Invalid XBR header size");

    // Check XBR frame header CRC
    int ret;
    if ((ret = bits_check_crc(&core->bits, header_pos, header_pos + header_size * 8 - 32)) < 0)
        return ret;

    // Number of channel sets
    int xbr_nchsets = bits_get(&core->bits, 2) + 1;

    // Channel set data byte size
    for (int i = 0; i < xbr_nchsets; i++)
        xbr_frame_size[i] = bits_get(&core->bits, 14) + 1;

    // Transition mode flag
    bool xbr_transition_mode = bits_get1(&core->bits);

    // Channel set headers
    int xbr_base_ch = 0;
    for (int i = 0; i < xbr_nchsets; i++) {
        xbr_nchannels[i] = bits_get(&core->bits, 3) + 1;
        int xbr_band_nbits = bits_get(&core->bits, 2) + 5;
        for (int ch = 0; ch < xbr_nchannels[i]; ch++) {
            xbr_nsubbands[xbr_base_ch + ch] = bits_get(&core->bits, xbr_band_nbits) + 1;
            enforce(xbr_nsubbands[xbr_base_ch + ch] <= MAX_SUBBANDS,
                    "Invalid number of active XBR subbands");
        }
        xbr_base_ch += xbr_nchannels[i];
    }

    if (flags & DCADEC_FLAG_STRICT)
        require(xbr_base_ch <= MAX_CHANNELS, "Too many XBR channels");

    // Reserved
    // Byte align
    // CRC16 of XBR frame header
    if ((ret = bits_seek(&core->bits, header_pos + header_size * 8 - 32)) < 0)
        return ret;

    // Channel set data
    xbr_base_ch = 0;
    for (int i = 0; i < xbr_nchsets; i++) {
        header_pos = core->bits.index;

        if (xbr_base_ch + xbr_nchannels[i] <= MAX_CHANNELS) {
            int sub_pos = 0;
            for (int sf = 0; sf < core->nsubframes; sf++)
                if ((ret = parse_xbr_subframe(core, xbr_base_ch,
                                              xbr_base_ch + xbr_nchannels[i],
                                              xbr_nsubbands, xbr_transition_mode,
                                              sf, &sub_pos)) < 0)
                    return ret;
        }

        xbr_base_ch += xbr_nchannels[i];

        if ((ret = bits_seek(&core->bits, header_pos + xbr_frame_size[i] * 8)) < 0)
            return ret;
    }

    return 0;
}

static int parse_x96_subband_samples(struct x96_decoder *x96, int ssf,
                                     int ch, int band, int sub_pos)
{
    // Subtract 1 from ABITS to account for VQ case (Table 6-8: Quantization
    // index code book select SEL96). ABITS = 0 and ABITS = 1 have already been
    // dealt with by the caller.
    int abits = x96->bit_allocation[ch][band] - 1;
    int audio[NUM_SUBBAND_SAMPLES];
    int ret, step_size;

    if ((ret = extract_audio(x96->core, audio, abits, x96->quant_index_sel[ch])) < 0)
        return ret;

    // Select quantization step size table
    // Look up quantization step size
    if (x96->core->bit_rate == -2)
        step_size = step_size_lossless[abits];
    else
        step_size = step_size_lossy[abits];

    dequantize(x96->subband_samples[ch][band] +
               sub_pos + ssf * NUM_SUBBAND_SAMPLES,
               audio, step_size,
               x96->scale_factors[ch][band], false);
    return 0;
}

#define NUM_VQ_X96  16

// Modified ISO/IEC 9899 linear congruential generator
// Returns pseudorandom integer in range [-2^30, 2^30 - 1]
static int rand_x96(struct x96_decoder *x96)
{
    x96->rand = 1103515245U * x96->rand + 12345U;
    return (x96->rand & 0x7fffffff) - 0x40000000;
}

static int parse_x96_subframe_audio(struct x96_decoder *x96, int sf, int xch_base, int *sub_pos)
{
    struct core_decoder *core = x96->core;
    int ssf, ch, band;

    // Number of subband samples in this subframe
    int nsamples = core->nsubsubframes[sf] * NUM_SUBBAND_SAMPLES;
    enforce(*sub_pos + nsamples <= core->npcmblocks, "Subband sample buffer overflow");

    // Number of VQ lookup iterations for this subframe
    int n_ssf_iter = core->nsubsubframes[sf] / 2;
    if (nsamples > n_ssf_iter * NUM_VQ_X96)
        n_ssf_iter++;

    // VQ encoded or unallocated subbands
    for (ch = xch_base; ch < x96->nchannels; ch++) {
        for (band = x96->subband_start; band < x96->nsubbands[ch]; band++) {
            // Get the sample pointer
            int *samples = x96->subband_samples[ch][band] + *sub_pos;

            // Get the scale factor
            int scale = x96->scale_factors[ch][band];

            int abits = x96->bit_allocation[ch][band];
            if (abits == 0) {   // No bits allocated for subband
                if (scale <= 1) {
                    memset(samples, 0, nsamples * sizeof(int));
                } else {
                    // Generate scaled random samples as required by specification
                    for (int n = 0; n < nsamples; n++)
                        samples[n] = mul31(rand_x96(x96), scale);
                }
            } else if (abits == 1) {    // VQ encoded subband
                for (int ssf_iter = 0; ssf_iter < n_ssf_iter; ssf_iter++) {
                    // Extract the VQ address from the bit stream
                    int vq_index = bits_get(&core->bits, 10);

                    // Look up the VQ code book for up to 16 subband samples
                    const int8_t *vq_samples = high_freq_samples[vq_index];

                    // Number of VQ samples to look up
                    int vq_nsamples = nsamples - ssf_iter * NUM_VQ_X96;
                    if (vq_nsamples > NUM_VQ_X96)
                        vq_nsamples = NUM_VQ_X96;

                    // Scale and take the samples
                    for (int n = 0; n < vq_nsamples; n++)
                        samples[n] = clip23(mul4(scale, vq_samples[n]));
                    samples += vq_nsamples;
                }
            }
        }
    }

    // Audio data
    for (ssf = 0; ssf < core->nsubsubframes[sf]; ssf++) {
        int ret;

        for (ch = xch_base; ch < x96->nchannels; ch++)
            for (band = x96->subband_start; band < x96->nsubbands[ch]; band++)
                // Not VQ encoded or unallocated subbands
                if (x96->bit_allocation[ch][band] > 1)
                    if ((ret = parse_x96_subband_samples(x96, ssf, ch, band, *sub_pos)) < 0)
                        return ret;

        // DSYNC
        if (ssf == core->nsubsubframes[sf] - 1 || core->sync_ssf)
            enforce(bits_get(&core->bits, 16) == 0xffff, "DSYNC check failed");
    }

    // Inverse ADPCM
    for (ch = xch_base; ch < x96->nchannels; ch++) {
        for (band = x96->subband_start; band < x96->nsubbands[ch]; band++) {
            // Only if prediction mode is on
            if (x96->prediction_mode[ch][band]) {
                int *samples = x96->subband_samples[ch][band] + *sub_pos;

                // Extract the VQ index
                int vq_index = x96->prediction_vq_index[ch][band];

                // Look up the VQ table for prediction coefficients
                const int16_t *vq_coeffs = adpcm_coeffs[vq_index];
                for (int m = 0; m < nsamples; m++) {
                    int64_t err = INT64_C(0);
                    for (int n = 0; n < NUM_ADPCM_COEFFS; n++)
                        err += (int64_t)samples[m - n - 1] * vq_coeffs[n];
                    samples[m] = clip23(samples[m] + clip23(norm13(err)));
                }
            }
        }
    }

    // Joint subband coding
    for (ch = xch_base; ch < x96->nchannels; ch++) {
        // Only if joint subband coding is enabled
        if (x96->joint_intensity_index[ch]) {
            // Get source channel
            int src_ch = x96->joint_intensity_index[ch] - 1;
            for (band = x96->nsubbands[ch]; band < x96->nsubbands[src_ch]; band++) {
                int *src = x96->subband_samples[src_ch][band] + *sub_pos;
                int *dst = x96->subband_samples[    ch][band] + *sub_pos;
                int scale = x96->joint_scale_factors[ch][band];
                for (int n = 0; n < nsamples; n++)
                    dst[n] = clip23(mul17(src[n], scale));
            }
        }
    }

    // Advance subband sample pointer for the next subframe
    *sub_pos += nsamples;
    return 0;
}

static void erase_x96_adpcm_history(struct x96_decoder *x96)
{
    // Erase ADPCM history from previous frame if
    // predictor history switch was disabled
    for (int ch = 0; ch < MAX_CHANNELS; ch++) {
        for (int band = 0; band < MAX_SUBBANDS_X96; band++) {
            int *samples = x96->subband_samples[ch][band] - NUM_ADPCM_COEFFS;
            for (int n = 0; n < NUM_ADPCM_COEFFS; n++)
                samples[n] = 0;
        }
    }
}

static int alloc_x96_sample_buffer(struct x96_decoder *x96)
{
    struct core_decoder *core = x96->core;
    int nchsamples = NUM_ADPCM_COEFFS + core->npcmblocks;
    int nframesamples = nchsamples * MAX_CHANNELS * MAX_SUBBANDS_X96;

    // Reallocate subband sample buffer
    int ret;
    if ((ret = dca_realloc(core, &x96->subband_buffer, nframesamples, sizeof(int))) < 0)
        return ret;
    if (ret > 0) {
        for (int ch = 0; ch < MAX_CHANNELS; ch++)
            for (int band = 0; band < MAX_SUBBANDS_X96; band++)
                x96->subband_samples[ch][band] = x96->subband_buffer +
                    (ch * MAX_SUBBANDS_X96 + band) * nchsamples + NUM_ADPCM_COEFFS;
    }

    if (!core->predictor_history)
        erase_x96_adpcm_history(x96);

    return 0;
}

static int parse_x96_subframe_header(struct x96_decoder *x96, int xch_base)
{
    struct core_decoder *core = x96->core;
    int ch, band, ret;

    // Prediction mode
    for (ch = xch_base; ch < x96->nchannels; ch++)
        for (band = x96->subband_start; band < x96->nsubbands[ch]; band++)
            x96->prediction_mode[ch][band] = bits_get1(&core->bits);

    // Prediction coefficients VQ address
    for (ch = xch_base; ch < x96->nchannels; ch++)
        for (band = x96->subband_start; band < x96->nsubbands[ch]; band++)
            if (x96->prediction_mode[ch][band])
                x96->prediction_vq_index[ch][band] = bits_get(&core->bits, 12);

    // Bit allocation index
    for (ch = xch_base; ch < x96->nchannels; ch++) {
        // Select codebook
        int sel = x96->bit_allocation_sel[ch];

        const struct huffman *huff;
        unsigned int abits_max;

        // Reuse quantization index code books for bit allocation index
        if (x96->high_res) {
            huff = &quant_index_huff_7[sel];
            abits_max = 15;
        } else {
            huff = &quant_index_huff_5[sel];
            abits_max = 7;
        }

        // Clear accumulation
        int abits = 0;

        for (band = x96->subband_start; band < x96->nsubbands[ch]; band++) {
            if (sel < 7)
                // If Huffman code was used, the difference of abits was encoded
                abits += bits_get_signed_vlc(&core->bits, huff);
            else
                abits = bits_get(&core->bits, 3 + x96->high_res);
            enforce((unsigned int)abits <= abits_max, "Invalid bit allocation index");
            x96->bit_allocation[ch][band] = abits;
        }
    }

    // Scale factors
    for (ch = xch_base; ch < x96->nchannels; ch++) {
        // Clear accumulation
        int scale_index = 0;

        // Extract scales for subbands
        // Transmitted even for unallocated subbands
        for (band = x96->subband_start; band < x96->nsubbands[ch]; band++) {
            if ((ret = parse_scale(core, &scale_index, x96->scale_factor_sel[ch])) < 0)
                return ret;
            x96->scale_factors[ch][band] = ret;
        }
    }

    // Joint subband codebook select
    for (ch = xch_base; ch < x96->nchannels; ch++) {
        // Only if joint subband coding is enabled
        if (x96->joint_intensity_index[ch]) {
            x96->joint_scale_sel[ch] = bits_get(&core->bits, 3);
            enforce(x96->joint_scale_sel[ch] < 7, "Invalid joint scale factor code book");
        }
    }

    // Scale factors for joint subband coding
    for (ch = xch_base; ch < x96->nchannels; ch++) {
        // Only if joint subband coding is enabled
        if (x96->joint_intensity_index[ch]) {
            // Select codebook
            int sel = x96->joint_scale_sel[ch];
            // Get source channel
            int src_ch = x96->joint_intensity_index[ch] - 1;
            for (band = x96->nsubbands[ch]; band < x96->nsubbands[src_ch]; band++) {
                if ((ret = parse_joint_scale(core, sel)) < 0)
                    return ret;
                x96->joint_scale_factors[ch][band] = ret;
            }
        }
    }

    // Side information CRC check word
    if (core->crc_present)
        bits_skip(&core->bits, 16);

    return 0;
}

static int parse_x96_coding_header(struct x96_decoder *x96, bool exss, int xch_base)
{
    struct core_decoder *core = x96->core;
    size_t header_pos = core->bits.index;
    size_t header_size = 0;
    int ch, n, ret;

    if (exss) {
        // Channel set header length
        header_size = bits_get(&core->bits, 7) + 1;

        // Check CRC
        if (x96->crc_present)
            if ((ret = bits_check_crc(&core->bits, header_pos, header_pos + header_size * 8)) < 0)
                return ret;
    }

    // High resolution flag
    x96->high_res = bits_get1(&core->bits);

    // First encoded subband
    if (x96->rev_no < 8) {
        x96->subband_start = bits_get(&core->bits, 5);
        enforce(x96->subband_start <= 27, "Invalid X96 subband start index");
    } else {
        x96->subband_start = 32;
    }

    // Subband activity count
    for (ch = xch_base; ch < x96->nchannels; ch++)
        x96->nsubbands[ch] = bits_get(&core->bits, 6) + 1;

    // Joint intensity coding index
    for (ch = xch_base; ch < x96->nchannels; ch++)
        x96->joint_intensity_index[ch] = bits_get(&core->bits, 3);

    // Scale factor code book
    for (ch = xch_base; ch < x96->nchannels; ch++) {
        x96->scale_factor_sel[ch] = bits_get(&core->bits, 3);
        enforce(x96->scale_factor_sel[ch] < 6, "Invalid scale factor code book");
    }

    // Bit allocation quantizer select
    for (ch = xch_base; ch < x96->nchannels; ch++)
        x96->bit_allocation_sel[ch] = bits_get(&core->bits, 3);

    // Quantization index codebook select
    for (n = 0; n < 6 + 4 * x96->high_res; n++)
        for (ch = xch_base; ch < x96->nchannels; ch++)
            x96->quant_index_sel[ch][n] = bits_get(&core->bits, quant_index_sel_nbits[n]);

    if (exss) {
        // Reserved
        // Byte align
        // CRC16 of channel set header
        if ((ret = bits_seek(&core->bits, header_pos + header_size * 8)) < 0)
            return ret;
    } else {
        if (core->crc_present)
            bits_skip(&core->bits, 16);
    }

    return 0;
}

static int parse_x96_frame_data(struct x96_decoder *x96, bool exss, int xch_base)
{
    struct core_decoder *core = x96->core;

    int ret;
    if ((ret = parse_x96_coding_header(x96, exss, xch_base)) < 0)
        return ret;

    int sub_pos = 0;
    for (int sf = 0; sf < core->nsubframes; sf++) {
        if ((ret = parse_x96_subframe_header(x96, xch_base)) < 0)
            return ret;
        if ((ret = parse_x96_subframe_audio(x96, sf, xch_base, &sub_pos)) < 0)
            return ret;
    }

    for (int ch = xch_base; ch < x96->nchannels; ch++) {
        // Number of active subbands for this channel
        int nsubbands;
        if (x96->joint_intensity_index[ch]) {
            nsubbands = x96->nsubbands[x96->joint_intensity_index[ch] - 1];
            if (nsubbands < x96->nsubbands[ch])
                nsubbands = x96->nsubbands[ch];
        } else {
            nsubbands = x96->nsubbands[ch];
        }

        // Update history for ADPCM
        // Clear inactive subbands
        for (int band = 0; band < MAX_SUBBANDS_X96; band++) {
            int *samples = x96->subband_samples[ch][band] - NUM_ADPCM_COEFFS;
            if (band >= x96->subband_start && band < nsubbands) {
                for (int n = NUM_ADPCM_COEFFS - 1; n >= 0; n--)
                    samples[n] = samples[core->npcmblocks + n];
            } else {
                memset(samples, 0, (NUM_ADPCM_COEFFS + core->npcmblocks) * sizeof(int));
            }
        }
    }

    return 0;
}

static int parse_x96_frame(struct x96_decoder *x96)
{
    struct core_decoder *core = x96->core;

    // Revision number
    x96->rev_no = bits_get(&core->bits, 4);
    require(x96->rev_no >= 1 && x96->rev_no <= 8, "Unsupported X96 revision");

    x96->crc_present = false;
    x96->nchannels = core->nchannels;

    int ret;
    if ((ret = alloc_x96_sample_buffer(x96)) < 0)
        return ret;

    if ((ret = parse_x96_frame_data(x96, false, 0)) < 0)
        return ret;

    // Seek to the end of core frame
    return bits_seek(&core->bits, core->frame_size * 8);
}

static int parse_x96_frame_exss(struct x96_decoder *x96, int flags)
{
    size_t  x96_frame_size[4];
    int     x96_nchannels[4];

    struct core_decoder *core = x96->core;
    size_t header_pos = core->bits.index;

    // X96 frame header length
    size_t header_size = bits_get(&core->bits, 6) + 1;
    enforce(header_size > 4, "Invalid X96 header size");

    size_t header_end = header_pos + header_size * 8 - 32;

    // Check X96 frame header CRC
    int ret;
    if ((ret = bits_check_crc(&core->bits, header_pos, header_end)) < 0)
        return ret;

    // Revision number
    x96->rev_no = bits_get(&core->bits, 4);
    require(x96->rev_no >= 1 && x96->rev_no <= 8, "Unsupported X96 revision");

    // CRC presence flag for channel set header
    x96->crc_present = bits_get1(&core->bits);

    // Number of channel sets
    int x96_nchsets = bits_get(&core->bits, 2) + 1;

    // Channel set data byte size
    for (int i = 0; i < x96_nchsets; i++)
        x96_frame_size[i] = bits_get(&core->bits, 12) + 1;

    // Number of channels in channel set
    int x96_base_ch = 0;
    for (int i = 0; i < x96_nchsets; i++) {
        x96_nchannels[i] = bits_get(&core->bits, 3) + 1;
        x96_base_ch += x96_nchannels[i];
    }

    if (flags & DCADEC_FLAG_STRICT)
        require(x96_base_ch <= MAX_CHANNELS, "Too many X96 channels");

    // Reserved
    // Byte align
    // CRC16 of X96 frame header
    if ((ret = bits_seek(&core->bits, header_end)) < 0)
        return ret;

    if ((ret = alloc_x96_sample_buffer(x96)) < 0)
        return ret;

    // Channel set data
    x96_base_ch = 0;
    for (int i = 0; i < x96_nchsets; i++) {
        header_pos = core->bits.index;

        if (x96_base_ch + x96_nchannels[i] <= MAX_CHANNELS) {
            x96->nchannels = x96_base_ch + x96_nchannels[i];
            if ((ret = parse_x96_frame_data(x96, true, x96_base_ch)) < 0)
                return ret;
        }

        x96_base_ch += x96_nchannels[i];

        if ((ret = bits_seek(&core->bits, header_pos + x96_frame_size[i] * 8)) < 0)
            return ret;
    }

    return 0;
}

// Revert to base core channel set in case (X)XCH parsing fails
static void revert_to_base_chset(struct core_decoder *core)
{
    core->nchannels = audio_mode_nch[core->audio_mode];
    core->ch_mask = audio_mode_ch_mask[core->audio_mode];
    core->dmix_coeffs_present = core->dmix_embedded = false;
}

static int parse_aux_data(struct core_decoder *core)
{
    // Auxiliary data byte count (can't be trusted)
    bits_skip(&core->bits, 6);

    // 4-byte align
    size_t aux_pos = bits_align4(&core->bits);

    // Auxiliary data sync word
    uint32_t sync = bits_get(&core->bits, 32);
    enforce(sync == SYNC_WORD_REV1AUX, "Invalid auxiliary data sync word");

    // Auxiliary decode time stamp flag
    if (bits_get1(&core->bits)) {
        bits_skip(&core->bits,  3); // 4-bit align
        bits_skip(&core->bits,  8); // MSB
        bits_skip(&core->bits,  4); // Marker
        bits_skip(&core->bits, 28); // LSB
        bits_skip(&core->bits,  4); // Marker
    }

    // Auxiliary dynamic downmix flag
    core->prim_dmix_embedded = bits_get1(&core->bits);

    if (core->prim_dmix_embedded) {
        // Auxiliary primary channel downmix type
        core->prim_dmix_type = bits_get(&core->bits, 3);
        enforce(core->prim_dmix_type < DMIX_TYPE_COUNT,
                "Invalid primary channel set downmix type");

        // Size of downmix coefficients matrix
        int m = dmix_primary_nch[core->prim_dmix_type];
        int n = audio_mode_nch[core->audio_mode] + !!core->lfe_present;

        // Dynamic downmix code coefficients
        int *coeff_ptr = core->prim_dmix_coeff;
        for (int i = 0; i < m * n; i++) {
            int code = bits_get(&core->bits, 9);
            int sign = (code >> 8) - 1; code &= 0xff;
            if (code) {
                unsigned int index = code - 1;
                enforce(index < dca_countof(dmix_table),
                        "Invalid downmix coefficient index");
                *coeff_ptr++ = (dmix_table[index] ^ sign) - sign;
            } else {
                *coeff_ptr++ = 0;
            }
        }
    }

    // Byte align
    bits_align1(&core->bits);

    // CRC16 of auxiliary data
    bits_skip(&core->bits, 16);

    // Check CRC
    return bits_check_crc(&core->bits, aux_pos + 32, core->bits.index);
}

static int parse_optional_info(struct core_decoder *core, int flags)
{
    int ret;

    // Time code stamp
    if (core->ts_present)
        bits_skip(&core->bits, 32);

    // Auxiliary data
    if (core->aux_present && (flags & DCADEC_FLAG_KEEP_DMIX_2CH)) {
        if ((ret = parse_aux_data(core)) < 0) {
            if (flags & DCADEC_FLAG_STRICT)
                return ret;
            core->prim_dmix_embedded = false;
        }
    } else {
        core->prim_dmix_embedded = false;
    }

    // Core extensions
    if (core->ext_audio_present && !(flags & DCADEC_FLAG_CORE_ONLY)) {
        size_t buf_size = (core->bits.total + 31) / 32;
        size_t sync_pos = (core->bits.index + 31) / 32;
        size_t last_pos = core->frame_size / 4;
        if (last_pos > buf_size)
            last_pos = buf_size;

        // Search for extension sync words aligned on 4-byte boundary
        size_t xch_pos = 0, xxch_pos = 0, x96_pos = 0, xbr_pos = 0;

        while (sync_pos < last_pos) {
            size_t hdr_size, dist;

            switch (core->bits.data[sync_pos]) {
            case DCA_32BE_const(SYNC_WORD_XCH):
                core->bits.index = (sync_pos + 1) * 32;
                hdr_size = bits_get(&core->bits, 10) + 1;
                // XCH comes last after all other extension streams. The
                // distance between XCH sync word and end of the core frame
                // must be equal to XCH frame size. Off by one error is
                // allowed for compatibility with legacy bitstreams.
                dist = core->frame_size - sync_pos * 4;
                if ((hdr_size == dist || hdr_size - 1 == dist)
                    && bits_get(&core->bits, 7) == 0x08) {
                    xch_pos = sync_pos + 1;
                    sync_pos = last_pos - 1;
                }
                break;

            case DCA_32BE_const(SYNC_WORD_XXCH):
                core->bits.index = (sync_pos + 1) * 32;
                hdr_size = bits_get(&core->bits, 6) + 1;
                if (!bits_check_crc(&core->bits, (sync_pos + 1) * 32,
                                    sync_pos * 32 + hdr_size * 8))
                    xxch_pos = sync_pos + 1;
                break;

            case DCA_32BE_const(SYNC_WORD_X96):
                // X96 comes last after all other extension streams (and can't
                // coexist with XCH apparently). The distance between X96 sync
                // word and end of the core frame must be equal to X96 frame
                // size.
                core->bits.index = (sync_pos + 1) * 32;
                hdr_size = bits_get(&core->bits, 12) + 1;
                dist = core->frame_size - sync_pos * 4;
                if (hdr_size == dist) {
                    x96_pos = sync_pos + 1;
                    sync_pos = last_pos - 1;
                }
                break;

            case DCA_32BE_const(SYNC_WORD_XBR):
                core->bits.index = (sync_pos + 1) * 32;
                hdr_size = bits_get(&core->bits, 6) + 1;
                if (!bits_check_crc(&core->bits, (sync_pos + 1) * 32,
                                    sync_pos * 32 + hdr_size * 8))
                    xbr_pos = sync_pos + 1;
                break;
            }

            sync_pos++;
        }

        if (xch_pos && !(flags & DCADEC_FLAG_KEEP_DMIX_MASK)) {
            //printf("found XCH @ %zu\n", xch_pos);
            core->bits.index = xch_pos * 32 + 17;
            if ((ret = parse_xch_frame(core)) < 0) {
                if (flags & DCADEC_FLAG_STRICT)
                    return ret;
                revert_to_base_chset(core);
            } else {
                core->xch_present = true;
            }
        }

        if (xxch_pos && !(flags & DCADEC_FLAG_KEEP_DMIX_MASK)) {
            //printf("found XXCH @ %zu\n", xxch_pos);
            core->bits.index = xxch_pos * 32;
            if ((ret = parse_xxch_frame(core)) < 0) {
                if (flags & DCADEC_FLAG_STRICT)
                    return ret;
                revert_to_base_chset(core);
            } else {
                core->xxch_present = true;
            }
        }

        if (x96_pos) {
            //printf("found X96 @ %zu\n", x96_pos);
            core->bits.index = x96_pos * 32 + 12;
            if (!core->x96_decoder) {
                if (!(core->x96_decoder = ta_znew(core, struct x96_decoder)))
                    return -DCADEC_ENOMEM;
                core->x96_decoder->core = core;
                core->x96_decoder->rand = 1;
            }
            if ((ret = parse_x96_frame(core->x96_decoder)) < 0) {
                if (flags & DCADEC_FLAG_STRICT)
                    return ret;
            } else {
                core->x96_present = true;
            }
        }

        if (xbr_pos) {
            //printf("found XBR @ %zu\n", xbr_pos);
            core->bits.index = xbr_pos * 32;
            if ((ret = parse_xbr_frame(core, flags)) < 0) {
                if (flags & DCADEC_FLAG_STRICT)
                    return ret;
            } else {
                core->xbr_present = true;
            }
        }
    }

    return 0;
}

int core_parse(struct core_decoder *core, uint8_t *data, size_t size,
               int flags, struct exss_asset *asset)
{
    core->xch_present = false;
    core->xxch_present = false;
    core->xbr_present = false;
    core->x96_present = false;

    if (asset) {
        bits_init(&core->bits, data + asset->core_offset, asset->core_size);
        if (bits_get(&core->bits, 32) != SYNC_WORD_CORE_EXSS)
            return -DCADEC_ENOSYNC;
    } else {
        bits_init(&core->bits, data, size);
        bits_skip(&core->bits, 32);
    }

    int ret;
    if ((ret = parse_frame_header(core)) < 0)
        return ret;
    if ((ret = alloc_sample_buffer(core)) < 0)
        return ret;
    if ((ret = parse_frame_data(core, HEADER_CORE, 0)) < 0)
        return ret;
    if ((ret = parse_optional_info(core, flags)) < 0)
        return ret;
    if ((ret = bits_seek(&core->bits, core->frame_size * 8)) < 0)
        return ret;
    return 0;
}

int core_parse_exss(struct core_decoder *core, uint8_t *data, size_t size,
                    int flags, struct exss_asset *asset)
{
    int ret;

    (void)size;

    if ((asset->extension_mask & EXSS_XXCH) && !core->xxch_present
        && !(flags & DCADEC_FLAG_KEEP_DMIX_MASK)) {
        //printf("found XXCH @ EXSS\n");
        bits_init(&core->bits, data + asset->xxch_offset, asset->xxch_size);
        if (bits_get(&core->bits, 32) == SYNC_WORD_XXCH) {
            if ((ret = parse_xxch_frame(core)) < 0) {
                if (flags & DCADEC_FLAG_STRICT)
                    return ret;
                revert_to_base_chset(core);
            } else {
                core->xxch_present = true;
            }
        } else if (flags & DCADEC_FLAG_STRICT) {
            return -DCADEC_ENOSYNC;
        }
    }

    if ((asset->extension_mask & EXSS_X96) && !core->x96_present) {
        //printf("found X96 @ EXSS\n");
        bits_init(&core->bits, data + asset->x96_offset, asset->x96_size);
        if (bits_get(&core->bits, 32) == SYNC_WORD_X96) {
            if (!core->x96_decoder) {
                if (!(core->x96_decoder = ta_znew(core, struct x96_decoder)))
                    return -DCADEC_ENOMEM;
                core->x96_decoder->core = core;
                core->x96_decoder->rand = 1;
            }
            if ((ret = parse_x96_frame_exss(core->x96_decoder, flags)) < 0) {
                if (flags & DCADEC_FLAG_STRICT)
                    return ret;
            } else {
                core->x96_present = true;
            }
        } else if (flags & DCADEC_FLAG_STRICT) {
            return -DCADEC_ENOSYNC;
        }
    }

    if ((asset->extension_mask & EXSS_XBR) && !core->xbr_present) {
        //printf("found XBR @ EXSS\n");
        bits_init(&core->bits, data + asset->xbr_offset, asset->xbr_size);
        if (bits_get(&core->bits, 32) == SYNC_WORD_XBR) {
            if ((ret = parse_xbr_frame(core, flags)) < 0) {
                if (flags & DCADEC_FLAG_STRICT)
                    return ret;
            } else {
                core->xbr_present = true;
            }
        } else if (flags & DCADEC_FLAG_STRICT) {
            return -DCADEC_ENOSYNC;
        }
    }

    return 0;
}

void core_clear(struct core_decoder *core)
{
    if (core) {
        if (core->subband_buffer) {
            erase_adpcm_history(core);
            memset(core->lfe_samples, 0, MAX_LFE_HISTORY * sizeof(int));
        }
        if (core->x96_decoder && core->x96_decoder->subband_buffer)
            erase_x96_adpcm_history(core->x96_decoder);
        for (int ch = 0; ch < MAX_CHANNELS; ch++)
            interpolator_clear(core->subband_dsp[ch]);
        core->output_history_lfe = 0;
    }
}

struct dcadec_core_info *core_get_info(struct core_decoder *core)
{
    struct dcadec_core_info *info = ta_znew(NULL, struct dcadec_core_info);
    if (!info)
        return NULL;
    info->nchannels = audio_mode_nch[core->audio_mode];
    info->audio_mode = core->audio_mode;
    info->lfe_present = core->lfe_present;
    info->sample_rate = core->sample_rate;
    info->source_pcm_res = core->source_pcm_res;
    info->es_format = core->es_format;
    info->bit_rate = core->bit_rate;
    info->npcmblocks = core->npcmblocks;
    info->xch_present = core->xch_present;
    info->xxch_present = core->xxch_present;
    info->xbr_present = core->xbr_present;
    info->x96_present = core->x96_present;
    return info;
}
