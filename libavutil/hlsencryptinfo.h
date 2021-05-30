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

#ifndef AVFORMAT_HLSENCRYPTINFO_H
#define AVFORMAT_HLSENCRYPTINFO_H

#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef __cplusplus
    extern "C" {
#endif

enum KeyType {
    KEY_NONE,
    KEY_AES_128,
    KEY_SAMPLE_AES,
    KEY_SAMPLE_SM4
};

#define MAX_URL_SIZE 4096

struct key_info {
     char encryptionKeyUri[MAX_URL_SIZE];
     char encryptionKeyRealUri[MAX_URL_SIZE];
     char encryptionMethod[64];
     char encryptionIvString[64];

     char encryptionVideoFormat[64];
     char encryptionKeyId[64];
     char encryptionKeyFormat[64];
     char encryptionKeyFormatVersions[64];
     char encryptionKeyString[64];
     unsigned char encryptionIv[16];
     unsigned char encryptionKey[16];
     int  isEncrypted;
};

void dump_key_info(struct key_info *hlsEncryptInfo);

#ifdef __cplusplus
    }
#endif
#endif /* AVFORMAT_HLSENCRYPTINFO_H */
