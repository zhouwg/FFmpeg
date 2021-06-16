/*
 * Apple HTTP Live Streaming demuxer
 * Copyright (c) 2021, Zhou Weiguo <zhouwg2000@gmail.com>
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "log.h"
#include "hlsencryptinfo.h"

void dump_key_info(struct KeyInfo *info)
{
    av_log(NULL, AV_LOG_INFO, "\tinfo->encryption_keyuir      : %s", info->encryption_keyuri);
    av_log(NULL, AV_LOG_INFO, "\tinfo->encryption_keyrealuri  : %s", info->encryption_keyrealuri);
    av_log(NULL, AV_LOG_INFO, "\tinfo->encryption_method      : %s", info->encryption_method);
    av_log(NULL, AV_LOG_INFO, "\tinfo->encryption_ivstring    : %s", info->encryption_ivstring);
    av_log(NULL, AV_LOG_INFO, "\tinfo->encryption_videoformat : %s", info->encryption_videoformat);
    av_log(NULL, AV_LOG_INFO, "\tinfo->encryption_keyidstring : %s", info->encryption_keyid);
    av_log(NULL, AV_LOG_INFO, "\tinfo->encryption_keyformat   : %s", info->encryption_keyformat);
    av_log(NULL, AV_LOG_INFO, "\tinfo->encryption_keyformatver: %s", info->encryption_keyformatversions);
    av_log(NULL, AV_LOG_INFO, "\tinfo->encryption_keystring   : %s", info->encryption_keystring);
    av_log(NULL, AV_LOG_INFO, "\tinfo->is_encrypted           : %d", info->is_encrypted);
    av_log(NULL, AV_LOG_INFO, "\tinfo->es_type                : %d", info->es_type);
    av_log(NULL, AV_LOG_INFO, "\tinfo->drm_sessionhandle      : %p", info->drm_sessionhandle);
    av_log(NULL, AV_LOG_INFO, "\tinfo->is_provisioned         : %d", info->is_provisioned);
}
