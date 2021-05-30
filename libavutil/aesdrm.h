/*
 *  decryptor for AES encrypted content
 *
 * Copyright (c) 2011-2017, John Chen
 *
 * Copyright (c) 2021, Zhou Weiguo<zhouwg2000@gmail.com>, porting to FFmpeg
 *
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

#ifndef AVUTIL_AESDRM_H
#define AVUTIL_AESDRM_H

#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <inttypes.h>

#include "openssl/aes.h"

#ifdef __cplusplus
    extern "C" {
#endif


#define AES_BLOCK_LENGTH_BYTES 16


enum esMode {
        H264,
        SAMPLE_AES_H264,
        SAMPLE_SM4_H264,
        H265,
        SAMPLE_AES_H265,
        SAMPLE_SM4_H265
};

enum DrmCryptoLevel {
   DRM_CRYPTO_ENCRYPT_UNKNOWN,
   DRM_CRYPTO_ENCRYPT_NONE,
   DRM_CRYPTO_ENCRYPT_CONTAINER_BASED,
   DRM_CRYPTO_ENCRYPT_ES_BASED
};

enum DrmCryptoInfoType {
    DRM_CRYPTO_IV = 0,
    DRM_CRYPTO_KEY,
    DRM_CRYPTO_MODE,
    DRM_CRYPTO_ENCRYPT_LEVEL,
    DRM_CRYPTO_NEED_DEPADDING
};

enum aesMode {
     AES_MODE_NONE = 0,
     AES_MODE_CTR,
     AES_MODE_CBC,
     AES_MODE_CHINADRM_CBC = 0x100
};

typedef int32_t AES_MODE;

typedef struct {
    void *value;
    uint32_t valueSize;
} DrmCryptoInfo;

typedef struct {
     uint32_t *numBytesOfClearData;
     uint32_t *numBytesOfEncryptedData;
     uint32_t numSubSamples;
} DrmBufferInfo;

typedef struct AesDecryptor{
    int32_t mEncryptLevel;  //DRM_CRYPTO_ENCRYPT_ES_BASED / DRM_CRYPTO_ENCRYPT_CONTAINER_BASED
    AES_MODE mMode;         //AES_MODE_NONE / AES_MODE_CTR / AES_MODE_CBC
    int32_t mNeedDepadding;

    uint8_t mKey[AES_BLOCK_LENGTH_BYTES];
    uint8_t mIv[AES_BLOCK_LENGTH_BYTES];
    pthread_mutex_t mLockDecryptor;

    int32_t (*setCryptoInfo)(struct AesDecryptor *ad, int32_t infoType, DrmCryptoInfo *pInfo);
    int32_t (*getCryptoInfo)(struct AesDecryptor *ad, int32_t infoType, DrmCryptoInfo *pInfo);
    int32_t (*decrypt)(struct AesDecryptor *ad, uint8_t* buffer, uint32_t *bufferSize, const DrmBufferInfo *pBufferInfo);
} AesDecryptor;


AesDecryptor* AesDecryptor_init(void);
void AesDecryptor_destroy(AesDecryptor *ad);

#ifdef __cplusplus
    }
#endif
#endif /* AVUTIL_AESDRM_H */
