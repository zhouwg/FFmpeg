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

void dump_key_info(struct key_info *info)
{
    av_log(NULL, AV_LOG_INFO, "\tinfo->encryptionKeyUri      : %s", info->encryptionKeyUri);
    av_log(NULL, AV_LOG_INFO, "\tinfo->encryptionKeyRealUri  : %s", info->encryptionKeyRealUri);
    av_log(NULL, AV_LOG_INFO, "\tinfo->encryptionMethod      : %s", info->encryptionMethod);
    av_log(NULL, AV_LOG_INFO, "\tinfo->encryptionIvString    : %s", info->encryptionIvString);
    av_log(NULL, AV_LOG_INFO, "\tinfo->encryptionVideoFormat : %s", info->encryptionVideoFormat);
    av_log(NULL, AV_LOG_INFO, "\tinfo->encryptionKeyIdString : %s", info->encryptionKeyId);
    av_log(NULL, AV_LOG_INFO, "\tinfo->encryptionKeyFormat   : %s", info->encryptionKeyFormat);
    av_log(NULL, AV_LOG_INFO, "\tinfo->encryptionKeyFormatVer: %s", info->encryptionKeyFormatVersions);
    av_log(NULL, AV_LOG_INFO, "\tinfo->encryptionKeyString   : %s", info->encryptionKeyString);
    av_log(NULL, AV_LOG_INFO, "\tinfo->isEncrypted           : %d", info->isEncrypted);
    av_log(NULL, AV_LOG_INFO, "\tinfo->drmSessionHandle      : %d", info->drmSessionHandle);
}
