/*
 * Apple HTTP Live Streaming decryptor
 *
 * Copyright (c) 2011-2017, John Chen
 *
 * Copyright (c) 2021, Zhou Weiguo<zhouwg2000@gmail.com>, porting to FFmpeg and add HLS Sample China-SM4-CBC and HLS China-SM4-CBC support
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

#include "log.h"
#include "avassert.h"
#include "hlsencryptinfo.h"
#include "hlsdecryptor.h"

#include "openssl/aes.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/bn.h"

#define PRE_CHECK(index, value, condition) do { if (!(condition)) { av_log(NULL, AV_LOG_WARNING, "index = %03d, value= %08d, value % 16 = %02d, it shouldn't happen, pls check...", (index), (value), (value) % 16); return -1; } } while(0)
#define CHECK(condition) do { if (!(condition)) { av_log(NULL, AV_LOG_WARNING, "error,pls check..."); return -1; } } while(0)
#define CHECK_EQ(x,y)    do { if ((x) != (y))   { av_log(NULL, AV_LOG_WARNING, "error,pls check..."); return -1; } } while(0)
#define CHECK_LE(x,y)    do { if ((x) >  (y))   { av_log(NULL, AV_LOG_WARNING, "error,pls check..."); return -1; } } while(0)
#define CHECK_LT(x,y)    do { if ((x) >= (y))   { av_log(NULL, AV_LOG_WARNING, "error,pls check..."); return -1; } } while(0)
#define CHECK_GE(x,y)    do { if ((x) <  (y))   { av_log(NULL, AV_LOG_WARNING, "error,pls check..."); return -1; } } while(0)
#define CHECK_GT(x,y)    do { if ((x) <= (y))   { av_log(NULL, AV_LOG_WARNING, "error,pls check..."); return -1; } } while(0)

static const EVP_CIPHER *sm4_get_mode(cryptoMode mode)
{
    switch (mode) {
        case CRYPTO_MODE_SM4_ECB:
            return EVP_sm4_ecb();
        case CRYPTO_MODE_SM4_CBC:
            return EVP_sm4_cbc();
        case CRYPTO_MODE_SM4_CFB:
            return EVP_sm4_cfb128();
        default:
            return NULL;
    }
}

static int32_t HLSDecryptor_sm4cbcDecryptInternal(HLSDecryptor *ad, uint8_t *buf, uint32_t bufLen, uint8_t *key, uint8_t *iv)
{
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher  = NULL;
    uint32_t outLen = 0;

    ctx     = EVP_CIPHER_CTX_new();
    if (NULL == ctx) {
        return -1;
    }
    cipher  = (EVP_CIPHER *)sm4_get_mode(CRYPTO_MODE_SM4_CBC);
    EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);

    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (!EVP_DecryptUpdate(ctx, buf, &outLen, buf, bufLen)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);

    av_assert0(bufLen == outLen);

    return 0;
}

static int32_t HLSDecryptor_sm4cbcDecrypt(HLSDecryptor *ad, uint8_t *buffer, uint32_t bufferSize, const DrmBufferInfo *pBufferInfo)
{
    uint32_t index  = 0;
    int32_t  result = 0;
    int32_t  size   = 0;
    size_t   i      = 0;
    size_t   offset = 0;

    //sanity check could be removed for production
    for (index = 0; index < pBufferInfo->numSubSamples; index++) {
        PRE_CHECK(index, pBufferInfo->numBytesOfEncryptedData[index], pBufferInfo->numBytesOfEncryptedData[index] % AES_BLOCK_LENGTH_BYTES == 0);
    }

    //section 6.2.3 in GY/T277-2019, http://www.nrta.gov.cn/art/2019/6/15/art_113_46189.html
    for (i = 0; i < pBufferInfo->numSubSamples; i++) {
        offset += pBufferInfo->numBytesOfClearData[i];
        PRE_CHECK(i, pBufferInfo->numBytesOfEncryptedData[i], pBufferInfo->numBytesOfEncryptedData[i] % AES_BLOCK_LENGTH_BYTES == 0);
        size = pBufferInfo->numBytesOfEncryptedData[i];
        if (size > 0) {
            uint8_t *ptr = buffer + offset;
            CHECK(size % AES_BLOCK_LENGTH_BYTES == 0);
            result = HLSDecryptor_sm4cbcDecryptInternal(ad, ptr, size, ad->mKey, ad->mIv);
            if (result != 0) {
                av_log(NULL, AV_LOG_WARNING, "sm4cbc decrypt failed");
                return result;
            }
            offset += pBufferInfo->numBytesOfEncryptedData[i];
        }
    }
    return result;
}

static int32_t HLSDecryptor_samplesm4cbcDecrypt(HLSDecryptor *ad, uint8_t *buffer, uint32_t bufferSize, const DrmBufferInfo *pBufferInfo)
{
    uint32_t index = 0;
    //sanity check could be removed for production
    for (index = 0; index < pBufferInfo->numSubSamples; index++) {
        PRE_CHECK(index, pBufferInfo->numBytesOfEncryptedData[index], pBufferInfo->numBytesOfEncryptedData[index] % AES_BLOCK_LENGTH_BYTES == 0);
    }

    //TODO: calling Sample China-SM4-CBC decrypt algo in openssl
    return 0;
}

static int32_t HLSDecryptor_aesDecryptInternal(HLSDecryptor *ad, uint8_t *buf, uint32_t bufLen, uint8_t *key, uint8_t *iv)
{
    AES_KEY aes_key;
    unsigned char aes_iv[AES_BLOCK_LENGTH_BYTES];

    if (ad->mCryptoMode == CRYPTO_MODE_NONE)
        return 0;

    if (AES_set_decrypt_key(key, AES_BLOCK_LENGTH_BYTES * 8, &aes_key) != 0) {
        return -1;
    }

    memcpy(aes_iv, iv, AES_BLOCK_LENGTH_BYTES);

    switch(ad->mCryptoMode) {
        case CRYPTO_MODE_AES_CTR:
        {
            //TODO: add CRYPTO_MODE_AES_CTR in next stage
        }
        break;

    case CRYPTO_MODE_AES_CBC:
        AES_cbc_encrypt(buf, buf, bufLen, &aes_key, aes_iv, AES_DECRYPT);
        break;

    default:
        return -1;
    }

    return 0;
}

static int32_t HLSDecryptor_decryptContainerBase(HLSDecryptor *ad, uint8_t *buffer, uint32_t *bufferSize)
{
    uint32_t encryptedDataSize = *bufferSize;
    int32_t  result = 0;
    size_t   n =  0;

    if (encryptedDataSize % AES_BLOCK_LENGTH_BYTES != 0) {
        av_log(NULL, AV_LOG_WARNING, "encrypted data is not 16 bytes alignment");
        return -1;
    }

    result = HLSDecryptor_aesDecryptInternal(ad, buffer, encryptedDataSize, ad->mKey, ad->mIv);
    if (result != 0) {
        av_log(NULL, AV_LOG_WARNING, "aes decrypt failed");
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

static int32_t HLSDecryptor_decryptEsBase(HLSDecryptor *ad, uint8_t *buffer, uint32_t bufferSize, const DrmBufferInfo *pBufferInfo)
{
    DrmBufferInfo info          = {0};
    uint32_t clearDataSize      = 0;
    uint32_t encryptedDataSize  = bufferSize;

    uint8_t *ptr    = NULL;
    int32_t result  = 0;
    int32_t size    = 0;
    size_t  i       = 0;
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
    for (i = 0; i < pBufferInfo->numSubSamples; i++) {
        offset += pBufferInfo->numBytesOfClearData[i];

        //the sub encrypted buffer size should be multiple of AES_BLOCK_LENGTH_BYTES,
        //otherwise following decrypt process need to be modified accordingly
        PRE_CHECK(i, pBufferInfo->numBytesOfEncryptedData[i], pBufferInfo->numBytesOfEncryptedData[i] % AES_BLOCK_LENGTH_BYTES == 0);

        size = pBufferInfo->numBytesOfEncryptedData[i];
        if (size > 0) {
            ptr = buffer + offset;
            CHECK(size % AES_BLOCK_LENGTH_BYTES == 0);
            memcpy(temp_iv, ptr + size - AES_BLOCK_LENGTH_BYTES, AES_BLOCK_LENGTH_BYTES);
            result = HLSDecryptor_aesDecryptInternal(ad, ptr, size, ad->mKey, packet_iv);
            if (result != 0) {
                av_log(NULL, AV_LOG_WARNING, "aes decrypt failed");
                return result;
            }
            memcpy(packet_iv, temp_iv, AES_BLOCK_LENGTH_BYTES);
            offset += pBufferInfo->numBytesOfEncryptedData[i];
        }
    }
    return result;
}

static int32_t HLSDecryptor_decrypt(HLSDecryptor *ad, uint8_t *buffer, uint32_t *bufferSize, const DrmBufferInfo *pBufferInfo)
{
    int ret = 0;
    if ((NULL == ad) || (CRYPTO_MODE_NONE == ad->mCryptoMode) || (ES_UNKNOWN == ad->mEsMode)) {
        return 0;
    }

    pthread_mutex_lock(&ad->mLockDecryptor);
    if (ES_H264_SAMPLE_AES == ad->mEsMode) {
        if (ad->mEncryptLevel == DRM_CRYPTO_ENCRYPT_ES_BASED) {
            ret =  HLSDecryptor_decryptEsBase(ad, buffer, *bufferSize, pBufferInfo);
        } else if (ad->mEncryptLevel == DRM_CRYPTO_ENCRYPT_CONTAINER_BASED) {
            ret =  HLSDecryptor_decryptContainerBase(ad, buffer,bufferSize);
        } else {
            ret = -1;
        }
    } else if (ES_H264_SAMPLE_SM4_CBC == ad->mEsMode) {
        ret = HLSDecryptor_samplesm4cbcDecrypt(ad, buffer, *bufferSize, pBufferInfo);
    } else if (ES_H264_SM4_CBC == ad->mEsMode) {
        ret = HLSDecryptor_sm4cbcDecrypt(ad, buffer, *bufferSize, pBufferInfo);
    }
    pthread_mutex_unlock(&ad->mLockDecryptor);

    return ret;
}

static int32_t HLSDecryptor_setCryptoInfo(HLSDecryptor *ad, int32_t infoCode, DrmCryptoInfo *pInfo)
{
    pthread_mutex_lock(&ad->mLockDecryptor);

    switch (infoCode) {
        case DRM_CRYPTO_CRYPTOMODE:
            ad->mCryptoMode = *((int32_t*)pInfo->value);
            break;
        case DRM_CRYPTO_ESMODE:
            ad->mEsMode = *((int32_t*)pInfo->value);
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

static int32_t HLSDecryptor_getCryptoInfo(HLSDecryptor *ad, int32_t infoCode, DrmCryptoInfo* pInfo)
{
    pthread_mutex_lock(&ad->mLockDecryptor);

    switch (infoCode) {
        case DRM_CRYPTO_CRYPTOMODE:
            pInfo->value = &ad->mCryptoMode;
            pInfo->valueSize = sizeof(ad->mCryptoMode);
            break;
        case DRM_CRYPTO_ESMODE:
            pInfo->value = &ad->mEsMode;
            pInfo->valueSize = sizeof(ad->mEsMode);
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

void HLSDecryptor_destroy(HLSDecryptor *ad)
{
    if (NULL == ad)
        return;

    pthread_mutex_destroy(&ad->mLockDecryptor);
    av_freep(&ad);
}

HLSDecryptor *HLSDecryptor_init()
{
    HLSDecryptor *aesdrm_decryptor = av_mallocz(sizeof(HLSDecryptor));
    if (NULL == aesdrm_decryptor) {
       return NULL;
    }

    aesdrm_decryptor->mEncryptLevel  = DRM_CRYPTO_ENCRYPT_ES_BASED;
    aesdrm_decryptor->mNeedDepadding = 1;
    aesdrm_decryptor->mCryptoMode    = CRYPTO_MODE_NONE;
    pthread_mutex_init(&aesdrm_decryptor->mLockDecryptor, NULL);

    aesdrm_decryptor->getCryptoInfo  = HLSDecryptor_getCryptoInfo;
    aesdrm_decryptor->setCryptoInfo  = HLSDecryptor_setCryptoInfo;
    aesdrm_decryptor->decrypt        = HLSDecryptor_decrypt;

    return aesdrm_decryptor;
}
