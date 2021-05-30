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
#include "hlsencryptinfo.h"
#include "libavutil/log.h"

void dump_key_info(struct key_info *info)
{
    LOGV("\tinfo->encryptionKeyUri      : %s", info->encryptionKeyUri);
    LOGV("\tinfo->encryptionKeyRealUri  : %s", info->encryptionKeyRealUri);
    LOGV("\tinfo->encryptionMethod      : %s", info->encryptionMethod);
    LOGV("\tinfo->encryptionIvString    : %s", info->encryptionIvString);
    LOGV("\tinfo->encryptionVideoFormat : %s", info->encryptionVideoFormat);
    LOGV("\tinfo->encryptionKeyId       : %s", info->encryptionKeyId);
    LOGV("\tinfo->encryptionKeyFormat   : %s", info->encryptionKeyFormat);
    LOGV("\tinfo->encryptionKeyFormatVer: %s", info->encryptionKeyFormatVersions);
    LOGV("\tinfo->encryptionKeyString   : %s", info->encryptionKeyString);
    LOGV("\tinfo->isEncrypted           : %d", info->isEncrypted);
}
