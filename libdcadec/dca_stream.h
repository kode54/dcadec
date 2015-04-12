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

#ifndef DCA_STREAM_H
#define DCA_STREAM_H

#include "dca_context.h"

#include <stdio.h>
#include <sys/types.h>

struct dcadec_stream;

struct dcadec_stream_callbacks
{
	int(*seek)(void * opaque, off_t offset, int whence);
	off_t(*tell)(void * opaque);
	int(*getc)(void * opaque);
	size_t(*read)(void * opaque, void * buf, size_t count);
};

DCADEC_API struct dcadec_stream *dcadec_stream_open(const struct dcadec_stream_callbacks * callbacks, void * opaque);
DCADEC_API void dcadec_stream_close(struct dcadec_stream *stream);
DCADEC_API int dcadec_stream_read(struct dcadec_stream *stream, uint8_t **data, size_t *size);
DCADEC_API int dcadec_stream_progress(struct dcadec_stream *stream);

void dcadec_stream_pack(uint8_t * out, const uint8_t * data, size_t count8, uint32_t sync);

#endif
