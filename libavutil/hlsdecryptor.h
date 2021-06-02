/*
 *  decryptor for HLS encrypted content
 *
 * Copyright (c) 2011-2017, John Chen
 *
 * Copyright (c) 2021, Zhou Weiguo<zhouwg2000@gmail.com>, porting to FFmpeg and add HLS Sample China-SM4-CBC and HLS China-SM4-CBC support
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

#ifndef AVUTIL_HLSDECRYPTOR_H
#define AVUTIL_HLSDECRYPTOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <inttypes.h>

#ifdef __cplusplus
    extern "C" {
#endif


#define AES_BLOCK_LENGTH_BYTES  16
#define SM4_BLOCK_LENGTH_BYTES  16


typedef enum esMode{
        ES_H264,
        ES_H264_SAMPLE_AES,
        ES_H264_SAMPLE_SM4_CBC,
        ES_H264_SM4_CBC,
        ES_H265,
        ES_H265_SAMPLE_AES,
        ES_H265_SAMPLE_SM4_CBC,
        ES_H265_SM4_CBC,
        ES_UNKNOWN
}esMode;

enum DrmCryptoLevel {
   DRM_CRYPTO_ENCRYPT_UNKNOWN,
   DRM_CRYPTO_ENCRYPT_NONE,
   DRM_CRYPTO_ENCRYPT_CONTAINER_BASED,
   DRM_CRYPTO_ENCRYPT_ES_BASED
};

enum DrmCryptoInfoType {
    DRM_CRYPTO_IV = 0,
    DRM_CRYPTO_KEY,
    DRM_CRYPTO_KEYID,
    DRM_CRYPTO_ESMODE,
    DRM_CRYPTO_CRYPTOMODE,
    DRM_CRYPTO_ENCRYPT_LEVEL,
    DRM_CRYPTO_NEED_DEPADDING
};


typedef enum cryptoMode {
     CRYPTO_MODE_NONE = 0,
     CRYPTO_MODE_AES_CTR  = 1,
     CRYPTO_MODE_AES_CBC  = 2,
     CRYPTO_MODE_SM4_ECB  = 3,
     CRYPTO_MODE_SM4_CBC  = 4,
     CRYPTO_MODE_SM4_CFB  = 5,
     CRYPTO_MODE_AES_CHINADRM_CBC  = 0x100
}cryptoMode;


typedef struct {
    void *value;
    uint32_t valueSize;
} DrmCryptoInfo;

typedef struct {
     uint32_t *numBytesOfClearData;
     uint32_t *numBytesOfEncryptedData;
     uint32_t numSubSamples;
} DrmBufferInfo;

typedef struct HLSDecryptor{
    int32_t mEncryptLevel;  //DRM_CRYPTO_ENCRYPT_ES_BASED / DRM_CRYPTO_ENCRYPT_CONTAINER_BASED
    cryptoMode mCryptoMode;
    esMode     mEsMode;
    int32_t mNeedDepadding;

    uint8_t mKey[AES_BLOCK_LENGTH_BYTES];
    uint8_t mKeyID[AES_BLOCK_LENGTH_BYTES];
    uint8_t mIv[AES_BLOCK_LENGTH_BYTES];
    pthread_mutex_t mLockDecryptor;

    int32_t (*setCryptoInfo)(struct HLSDecryptor *ad, int32_t infoType, DrmCryptoInfo *pInfo);
    int32_t (*getCryptoInfo)(struct HLSDecryptor *ad, int32_t infoType, DrmCryptoInfo *pInfo);
    int32_t (*decrypt)(struct HLSDecryptor *ad, uint8_t* buffer, uint32_t *bufferSize, const DrmBufferInfo *pBufferInfo);
} HLSDecryptor;


HLSDecryptor* HLSDecryptor_init(void);
void HLSDecryptor_destroy(HLSDecryptor *ad);

#ifdef __cplusplus
    }
#endif
#endif /* AVUTIL_HLSDECRYPTOR_H */
