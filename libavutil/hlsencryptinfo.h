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

typedef enum KeyType {
    KEY_AES_128,
    KEY_SAMPLE_AES,
    KEY_SAMPLE_SM4_CBC,
    KEY_SM4_CBC,
    KEY_NONE
}KeyType;

typedef enum ESType{
    ES_H264,
    ES_H264_SAMPLE_AES,
    ES_H264_SAMPLE_SM4_CBC,
    ES_H264_SM4_CBC,
    ES_H265,
    ES_H265_SAMPLE_AES,
    ES_H265_SAMPLE_SM4_CBC,
    ES_H265_SM4_CBC,
    ES_UNKNOWN
}ESType;

#define MAX_URL_SIZE            4096
#define KEY_LENGTH_BYTES        16
#define IV_LENGTH_BYTES         16
#define CEI_UUID_LENGTH         16
#define KEYINFO_ITEM_LENGTH     64

struct KeyInfo {
     unsigned char encryption_keyuri[MAX_URL_SIZE];
     unsigned char encryption_keyrealuri[MAX_URL_SIZE];
     unsigned char encryption_method[KEYINFO_ITEM_LENGTH];
     unsigned char encryption_videoformat[KEYINFO_ITEM_LENGTH];
     unsigned char encryption_ivstring[KEYINFO_ITEM_LENGTH];
     unsigned char encryption_keystring[KEYINFO_ITEM_LENGTH];
     unsigned char encryption_keyidstring[KEYINFO_ITEM_LENGTH];
     unsigned char encryption_keyformat[KEYINFO_ITEM_LENGTH];
     unsigned char encryption_keyformatversions[KEYINFO_ITEM_LENGTH];
     unsigned char encryption_iv[IV_LENGTH_BYTES];
     unsigned char encryption_key[KEY_LENGTH_BYTES];
     unsigned char encryption_keyid[KEY_LENGTH_BYTES];

     ESType es_type;
     int  is_encrypted;
     int  is_provisioned;
     void *drm_sessionhandle;
};

void dump_key_info(struct KeyInfo *hls_encryptinfo);

#ifdef __cplusplus
    }
#endif
#endif /* AVFORMAT_HLSENCRYPTINFO_H */
