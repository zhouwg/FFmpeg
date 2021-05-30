/*
 * Apple HTTP Live Streaming demuxer
 *
 * Copyright (c) 2011-2017, John Chen
 *
 * Copyright (c) 2021, Zhou Weiguo<zhouwg2000@gmail.com>, porting to FFmpeg
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

#include <pthread.h>

#include "aesdrm.h"
#include "log.h"
#include "hlsencryptinfo.h"

#define CHECK(condition) do { if (!(condition)) { LOGW("error"); return -1; } } while(0)
#define CHECK_EQ(x,y)    do { if ((x) != (y))   { LOGW("error"); return -1; } } while(0)
#define CHECK_LE(x,y)    do { if ((x) >  (y))   { LOGW("error"); return -1; } } while(0)
#define CHECK_LT(x,y)    do { if ((x) >= (y))   { LOGW("error"); return -1; } } while(0)
#define CHECK_GE(x,y)    do { if ((x) <  (y))   { LOGW("error"); return -1; } } while(0)
#define CHECK_GT(x,y)    do { if ((x) <= (y))   { LOGW("error"); return -1; } } while(0)


static int32_t AesDecryptor_aesDecryptInternal(AesDecryptor *ad, uint8_t *buf, uint32_t bufLen, uint8_t *key, uint8_t *iv)
{
    AES_KEY aes_key;
    unsigned char aes_iv[AES_BLOCK_LENGTH_BYTES];

    if (ad->mMode == AES_MODE_NONE)
        return 0;

    if (AES_set_decrypt_key(key, AES_BLOCK_LENGTH_BYTES * 8, &aes_key) != 0) {
        return -1;
    }

    memcpy(aes_iv, iv, AES_BLOCK_LENGTH_BYTES);

    switch(ad->mMode) {
        case AES_MODE_CTR:
        {
            //TODO: add AES_MODE_CTR in next stage
        }

        break;
    case AES_MODE_CBC:
        AES_cbc_encrypt(buf, buf, bufLen, &aes_key, aes_iv, AES_DECRYPT);
        break;

    default:
        return -1;
    }

    return 0;
}

static int32_t AesDecryptor_decryptContainerBase(AesDecryptor *ad, uint8_t *buffer, uint32_t *bufferSize)
{
    uint32_t encryptedDataSize = *bufferSize;
    int32_t  result = 0;
    size_t   n =  0;

    if (encryptedDataSize % AES_BLOCK_LENGTH_BYTES != 0) {
        return -1;
    }

    result = AesDecryptor_aesDecryptInternal(ad, buffer, encryptedDataSize, ad->mKey, ad->mIv);
    if (result != 0) {
        return result;
    }

    n = encryptedDataSize;
    CHECK_GT(n, 0u);

    if (ad->mNeedDepadding) {
        size_t pad = buffer[n - 1];
        CHECK_GT(pad, 0u);
        CHECK_LE(pad, 16u);
        CHECK_GE((size_t)n, pad);
        for (size_t i = 0; i < pad; ++i) {
            CHECK_EQ((unsigned)buffer[n - 1 - i], pad);
        }

        n -= pad;
    }
    *bufferSize = n;

    return result;
}

static int32_t AesDecryptor_decryptEsBase(AesDecryptor *ad, uint8_t *buffer, uint32_t bufferSize, const DrmBufferInfo *pBufferInfo)
{
    DrmBufferInfo info          = {0};
    uint32_t clearDataSize      = 0;
    uint32_t encryptedDataSize  = bufferSize;

    int32_t result  = 0;
    size_t  offset  = 0;
    uint8_t packet_iv[AES_BLOCK_LENGTH_BYTES];
    uint8_t temp_iv[AES_BLOCK_LENGTH_BYTES];

    if (NULL == pBufferInfo) {
        info.numBytesOfClearData     = &clearDataSize;
        info.numBytesOfEncryptedData = &encryptedDataSize;
        info.numSubSamples           = 1;
        pBufferInfo                  = &info;
    }

    memcpy(packet_iv, ad->mIv, AES_BLOCK_LENGTH_BYTES);
    for(size_t i = 0; i < pBufferInfo->numSubSamples; i++) {
        offset += pBufferInfo->numBytesOfClearData[i];

        //the sub encrypted buffer size should be multiple of AES_BLOCK_LENGTH_BYTES,
        //otherwise following decrypt process need to be modified accordingly
        CHECK(pBufferInfo->numBytesOfEncryptedData[i] % AES_BLOCK_LENGTH_BYTES == 0);

        int32_t size = pBufferInfo->numBytesOfEncryptedData[i];
        if (size > 0) {
            uint8_t *ptr = buffer + offset;
            CHECK(size % AES_BLOCK_LENGTH_BYTES == 0);
            memcpy(temp_iv, ptr + size - AES_BLOCK_LENGTH_BYTES, AES_BLOCK_LENGTH_BYTES);
            result = AesDecryptor_aesDecryptInternal(ad, ptr, size, ad->mKey, packet_iv);
            if (result != 0) {
                return result;
            }
            offset += pBufferInfo->numBytesOfEncryptedData[i];
            memcpy(packet_iv, temp_iv, AES_BLOCK_LENGTH_BYTES);
        }
    }
    return result;
}

static int32_t AesDecryptor_decrypt(AesDecryptor *ad, uint8_t *buffer, uint32_t *bufferSize, const DrmBufferInfo *pBufferInfo)
{
    int ret = 0;
    if ((NULL == ad) || (ad->mMode == AES_MODE_NONE)) {
        return 0;
    }

    pthread_mutex_lock(&ad->mLockDecryptor);
    if (ad->mEncryptLevel == DRM_CRYPTO_ENCRYPT_ES_BASED) {
        ret =  AesDecryptor_decryptEsBase(ad, buffer, *bufferSize, pBufferInfo);
    } else if (ad->mEncryptLevel == DRM_CRYPTO_ENCRYPT_CONTAINER_BASED) {
        ret =  AesDecryptor_decryptContainerBase(ad, buffer,bufferSize);
    } else {
        ret = -1;
    }
    pthread_mutex_unlock(&ad->mLockDecryptor);

    return ret;
}

static int32_t AesDecryptor_setCryptoInfo(AesDecryptor *ad, int32_t infoCode, DrmCryptoInfo *pInfo)
{
    pthread_mutex_lock(&ad->mLockDecryptor);

    switch (infoCode) {
        case DRM_CRYPTO_MODE:
            ad->mMode = *((int32_t*)pInfo->value);
            break;
        case DRM_CRYPTO_KEY:
            CHECK(pInfo->valueSize == AES_BLOCK_LENGTH_BYTES);
            memcpy(ad->mKey, pInfo->value, pInfo->valueSize);
            break;
        case DRM_CRYPTO_IV:
            CHECK(pInfo->valueSize == AES_BLOCK_LENGTH_BYTES);
            memcpy(ad->mIv, pInfo->value, pInfo->valueSize);
            break;
        case DRM_CRYPTO_ENCRYPT_LEVEL:
            ad->mEncryptLevel = *((int32_t*)pInfo->value);
            break;
        case DRM_CRYPTO_NEED_DEPADDING:
            ad->mNeedDepadding = *((int32_t*)pInfo->value);
            break;
        default:
            break;
    }
    pthread_mutex_unlock(&ad->mLockDecryptor);

    return 0;
}


static int32_t AesDecryptor_getCryptoInfo(AesDecryptor *ad, int32_t infoCode, DrmCryptoInfo* pInfo)
{
    pthread_mutex_lock(&ad->mLockDecryptor);

    switch (infoCode) {
        case DRM_CRYPTO_MODE:
            pInfo->value = &ad->mMode;
            pInfo->valueSize = sizeof(ad->mMode);
            break;
        case DRM_CRYPTO_ENCRYPT_LEVEL:
            pInfo->valueSize = sizeof(ad->mEncryptLevel);
            *((int32_t*)pInfo->value) = ad->mEncryptLevel;
            break;
        case DRM_CRYPTO_NEED_DEPADDING:
            pInfo->valueSize = sizeof(ad->mNeedDepadding);
            *((int32_t*)pInfo->value) = ad->mNeedDepadding;
            break;
        default:
            pInfo->value = NULL;
            pInfo->valueSize = 0;
            break;
    }
    pthread_mutex_unlock(&ad->mLockDecryptor);

    return 0;
}




void AesDecryptor_destroy(AesDecryptor *ad)
{
    if (NULL == ad)
        return;

    pthread_mutex_destroy(&ad->mLockDecryptor);
    av_freep(&ad);
}


AesDecryptor *AesDecryptor_init()
{
    int ret = 0;

    AesDecryptor *aesdrm_decryptor = av_mallocz(sizeof(AesDecryptor));
    if (NULL == aesdrm_decryptor) {
       ret = AVERROR(ENOMEM);
       return NULL;
    }

    aesdrm_decryptor->mEncryptLevel  = DRM_CRYPTO_ENCRYPT_ES_BASED;
    aesdrm_decryptor->mNeedDepadding = 1;
    aesdrm_decryptor->mMode          = AES_MODE_NONE;
    pthread_mutex_init(&aesdrm_decryptor->mLockDecryptor, NULL);

    aesdrm_decryptor->getCryptoInfo   = AesDecryptor_getCryptoInfo;
    aesdrm_decryptor->setCryptoInfo   = AesDecryptor_setCryptoInfo;
    aesdrm_decryptor->decrypt         = AesDecryptor_decrypt;

    return aesdrm_decryptor;
}
