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

#include "log.h"
#include "avassert.h"
#include "hlsencryptinfo.h"
#include "hlsdecryptor.h"

#include "openssl/aes.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/bn.h"

#include "libavcodec/h264.h"
#include "libavcodec/hevc.h"

#define PRE_CHECK(index, value, condition) do { if (!(condition)) { av_log(NULL, AV_LOG_WARNING, "index = %03d, value= %08d, value % 16 = %02d, it shouldn't happen, pls check...", (index), (value), (value) % 16); return -1; } } while(0)
#define CHECK(condition) do { if (!(condition)) { av_log(NULL, AV_LOG_WARNING, "error,pls check..."); return -1; } } while(0)
#define CHECK_EQ(x,y)    do { if ((x) != (y))   { av_log(NULL, AV_LOG_WARNING, "error,pls check..."); return -1; } } while(0)
#define CHECK_LE(x,y)    do { if ((x) >  (y))   { av_log(NULL, AV_LOG_WARNING, "error,pls check..."); return -1; } } while(0)
#define CHECK_LT(x,y)    do { if ((x) >= (y))   { av_log(NULL, AV_LOG_WARNING, "error,pls check..."); return -1; } } while(0)
#define CHECK_GE(x,y)    do { if ((x) <  (y))   { av_log(NULL, AV_LOG_WARNING, "error,pls check..."); return -1; } } while(0)
#define CHECK_GT(x,y)    do { if ((x) <= (y))   { av_log(NULL, AV_LOG_WARNING, "error,pls check..."); return -1; } } while(0)

static const EVP_CIPHER *sm4_get_mode(DrmCryptoMode mode)
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

static int32_t hlsdecryptor_sm4cbc_decrypt_internal(HLSDecryptor *ad, uint8_t *buffer, uint32_t bufferSize, uint8_t *key, uint8_t *iv)
{
    uint32_t outLen = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher  = NULL;

    ctx     = EVP_CIPHER_CTX_new();
    if (NULL == ctx) {
        return -1;
    }
    cipher  = (EVP_CIPHER *)sm4_get_mode(CRYPTO_MODE_SM4_CBC);
    EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);

    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (!EVP_DecryptUpdate(ctx, buffer, &outLen, buffer, bufferSize)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);

    av_assert0(bufferSize == outLen);

    return 0;
}

static int32_t hlsdecryptor_sm4cbc_decrypt(HLSDecryptor *ad, uint8_t *buffer, uint32_t bufferSize, const DrmBufferInfo *pBufferInfo)
{
    uint8_t* ptr    = NULL;
    uint32_t index  = 0;
    uint32_t offset = 0;
    uint32_t size   = 0;
    int32_t  result = 0;

    //sanity check could be removed for production
    for (index = 0; index < pBufferInfo->num_subsamples; index++) {
        PRE_CHECK(index, pBufferInfo->num_encrypteddata[index], pBufferInfo->num_encrypteddata[index] % AES_BLOCK_LENGTH_BYTES == 0);
    }

    //section 6.2.3 in GY/T277-2019, http://www.nrta.gov.cn/art/2019/6/15/art_113_46189.html
    for (index = 0; index < pBufferInfo->num_subsamples; index++) {
        offset += pBufferInfo->num_cleardata[index];
        PRE_CHECK(index, pBufferInfo->num_encrypteddata[index], pBufferInfo->num_encrypteddata[index] % AES_BLOCK_LENGTH_BYTES == 0);
        size = pBufferInfo->num_encrypteddata[index];
        if (size > 0) {
            ptr = buffer + offset;
            CHECK(size % SM4_BLOCK_LENGTH_BYTES == 0);
            result = hlsdecryptor_sm4cbc_decrypt_internal(ad, ptr, size, ad->key, ad->iv);
            if (result != 0) {
                av_log(NULL, AV_LOG_WARNING, "sm4cbc decrypt failed");
                return result;
            }
            offset += pBufferInfo->num_encrypteddata[index];
        }
    }
    return result;
}

static int32_t hlsdecryptor_samplesm4cbc_decrypt(HLSDecryptor *ad, uint8_t *buffer, uint32_t bufferSize, const DrmBufferInfo *pBufferInfo)
{
    uint8_t* ptr    = NULL;
    uint32_t index  = 0;
    uint32_t offset = 0;
    uint32_t size   = 0;
    int32_t  result = 0;

    //sanity check could be removed for production
    for (index = 0; index < pBufferInfo->num_subsamples; index++) {
        PRE_CHECK(index, pBufferInfo->num_encrypteddata[index], pBufferInfo->num_encrypteddata[index] % AES_BLOCK_LENGTH_BYTES == 0);
    }

    //TODO:Sample SM4-CBC not working at the moment

    return result;
}

static int32_t hlsdecryptor_aes_decrypt_internal(HLSDecryptor *ad, uint8_t *buffer, uint32_t bufferSize, uint8_t *key, uint8_t *iv)
{
    AES_KEY aes_key;
    uint8_t aes_iv[AES_BLOCK_LENGTH_BYTES];

    if (AES_set_decrypt_key(key, AES_BLOCK_LENGTH_BYTES * 8, &aes_key) != 0) {
        return -1;
    }

    memcpy(aes_iv, iv, AES_BLOCK_LENGTH_BYTES);

    switch (ad->crypto_mode) {
        case CRYPTO_MODE_AES_CTR:
        {
            //TODO: add CRYPTO_MODE_AES_CTR in next stage
        }
        break;

    case CRYPTO_MODE_AES_CBC:
        AES_cbc_encrypt(buffer, buffer, bufferSize, &aes_key, aes_iv, AES_DECRYPT);
        break;

    default:
        return -1;
    }

    return 0;
}

static int32_t hlsdecryptor_decrypt_containerbase(HLSDecryptor *ad, uint8_t *buffer, uint32_t *bufferSize)
{
    uint32_t n =  0;
    uint32_t encryptedDataSize = *bufferSize;
    int32_t  result = 0;

    if (encryptedDataSize % AES_BLOCK_LENGTH_BYTES != 0) {
        av_log(NULL, AV_LOG_WARNING, "encrypted data is not 16 bytes alignment");
        return -1;
    }

    result = hlsdecryptor_aes_decrypt_internal(ad, buffer, encryptedDataSize, ad->key, ad->iv);
    if (result != 0) {
        av_log(NULL, AV_LOG_WARNING, "aes decrypt failed");
        return result;
    }

    n = encryptedDataSize;
    CHECK_GT(n, 0u);

    if (ad->need_depadding) {
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

static int32_t hlsdecryptor_decrypt_esbase(HLSDecryptor *ad, uint8_t *buffer, uint32_t bufferSize, const DrmBufferInfo *pBufferInfo)
{
    DrmBufferInfo info          = {0};
    uint32_t clearDataSize      = 0;
    uint32_t encryptedDataSize  = bufferSize;

    uint32_t size    = 0;
    uint32_t index   = 0;
    uint32_t offset  = 0;
    int32_t result   = 0;
    uint8_t *ptr     = NULL;
    uint8_t packet_iv[AES_BLOCK_LENGTH_BYTES];
    uint8_t temp_iv[AES_BLOCK_LENGTH_BYTES];

    if (NULL == pBufferInfo) {
        info.num_cleardata     = &clearDataSize;
        info.num_encrypteddata = &encryptedDataSize;
        info.num_subsamples           = 1;
        pBufferInfo                  = &info;
    }

    memcpy(packet_iv, ad->iv, AES_BLOCK_LENGTH_BYTES);
    for (index = 0; index < pBufferInfo->num_subsamples; index++) {
        offset += pBufferInfo->num_cleardata[index];

        //the sub encrypted buffer size should be multiple of AES_BLOCK_LENGTH_BYTES,
        //otherwise following decrypt process need to be modified accordingly
        PRE_CHECK(index, pBufferInfo->num_encrypteddata[index], pBufferInfo->num_encrypteddata[index] % AES_BLOCK_LENGTH_BYTES == 0);

        size = pBufferInfo->num_encrypteddata[index];
        if (size > 0) {
            ptr = buffer + offset;
            CHECK(size % AES_BLOCK_LENGTH_BYTES == 0);
            memcpy(temp_iv, ptr + size - AES_BLOCK_LENGTH_BYTES, AES_BLOCK_LENGTH_BYTES);
            result = hlsdecryptor_aes_decrypt_internal(ad, ptr, size, ad->key, packet_iv);
            if (result != 0) {
                av_log(NULL, AV_LOG_WARNING, "aes decrypt failed");
                return result;
            }
            memcpy(packet_iv, temp_iv, AES_BLOCK_LENGTH_BYTES);
            offset += pBufferInfo->num_encrypteddata[index];
        }
    }
    return result;
}

static int32_t hlsdecryptor_set_cryptoinfo(HLSDecryptor *ad, DrmCryptoInfoType infoCode, DrmCryptoInfo *pInfo)
{
    pthread_mutex_lock(&ad->lock_decryptor);

    switch (infoCode) {
        case DRM_CRYPTO_CRYPTOMODE:
            ad->crypto_mode = *((int32_t*)pInfo->value);
            break;
        case DRM_CRYPTO_ESMODE:
            ad->es_type = *((int32_t*)pInfo->value);
            break;
        case DRM_CRYPTO_KEY:
            CHECK(pInfo->value_size == AES_BLOCK_LENGTH_BYTES);
            memcpy(ad->key, pInfo->value, pInfo->value_size);
            break;
        case DRM_CRYPTO_IV:
            CHECK(pInfo->value_size == AES_BLOCK_LENGTH_BYTES);
            memcpy(ad->iv, pInfo->value, pInfo->value_size);
            break;
        case DRM_CRYPTO_ENCRYPT_LEVEL:
            ad->encrypt_level = *((int32_t*)pInfo->value);
            break;
        case DRM_CRYPTO_NEED_DEPADDING:
            ad->need_depadding = *((int32_t*)pInfo->value);
            break;
        default:
            break;
    }
    pthread_mutex_unlock(&ad->lock_decryptor);

    return 0;
}

static int32_t hlsdecryptor_get_cryptoinfo(HLSDecryptor *ad, DrmCryptoInfoType infoCode, DrmCryptoInfo* pInfo)
{
    pthread_mutex_lock(&ad->lock_decryptor);

    switch (infoCode) {
        case DRM_CRYPTO_CRYPTOMODE:
            pInfo->value = &ad->crypto_mode;
            pInfo->value_size = sizeof(ad->crypto_mode);
            break;
        case DRM_CRYPTO_ESMODE:
            pInfo->value = &ad->es_type;
            pInfo->value_size = sizeof(ad->es_type);
            break;
        case DRM_CRYPTO_ENCRYPT_LEVEL:
            pInfo->value_size = sizeof(ad->encrypt_level);
            *((int32_t*)pInfo->value) = ad->encrypt_level;
            break;
        case DRM_CRYPTO_NEED_DEPADDING:
            pInfo->value_size = sizeof(ad->need_depadding);
            *((int32_t*)pInfo->value) = ad->need_depadding;
            break;
        default:
            pInfo->value = NULL;
            pInfo->value_size = 0;
            break;
    }
    pthread_mutex_unlock(&ad->lock_decryptor);

    return 0;
}

/**
* @param buffer          stripped encrypted IDR/Slice data, beginning with NALU type bytes
* @param pbuffer_size    pointer of size of stripped encrypted data
*/
#define min(a, b) ((a) < (b) ? (a) : (b))
#define bool uint8_t
#define true 1
#define false 0
static int32_t hlsdecryptor_decrypt(HLSDecryptor *ad, uint8_t *buffer, uint32_t *pbuffer_size)
{
    uint32_t *clear_bytes   = NULL;
    uint32_t *encrypt_bytes = NULL;

    uint32_t clear_index    = 0;
    uint32_t encrypt_index  = 0;
    uint32_t num_samples    = 0;
    uint32_t buffer_size    = *pbuffer_size;
    uint32_t tmp_nal_size   = buffer_size;

    int8_t   naltype                  = -1;
    int32_t  result                   = 0;
    bool     is_encrypted_naltype     = 0;
    struct   KeyInfo *hls_encryptinfo = NULL;

    if ((NULL == ad) || (CRYPTO_MODE_NONE == ad->crypto_mode) || (ES_UNKNOWN == ad->es_type)) {
        return -1;
    }

    if ((NULL == buffer) || (buffer_size <= 0)) {
        return -1;
    }

    av_assert0(NULL != ad->apc);
    av_assert0(NULL != ad->apc->hls_encryptinfo);
    hls_encryptinfo = ad->apc->hls_encryptinfo;

    if ((ES_H264_SAMPLE_AES == hls_encryptinfo->es_type) || (ES_H264_SM4_CBC == hls_encryptinfo->es_type)|| (ES_H264_SAMPLE_SM4_CBC == hls_encryptinfo->es_type)) {
        naltype = buffer[0] & 0x1f;
        is_encrypted_naltype = true;
        bool SEI = (naltype == 6);
        if (SEI) {
            is_encrypted_naltype = false;
        }
        is_encrypted_naltype = (naltype == H264_NAL_SLICE || naltype == H264_NAL_IDR_SLICE);

    } else if (ES_H265_SAMPLE_AES == hls_encryptinfo->es_type) {
        naltype = (buffer[0] & 0x7E) >> 1;
        is_encrypted_naltype = true;
        bool SEI = (naltype == HEVC_NAL_SEI_PREFIX || naltype == HEVC_NAL_SEI_SUFFIX);
        if (SEI) {
            is_encrypted_naltype = false;
        }
        is_encrypted_naltype = ((naltype >= 0 && naltype <= HEVC_NAL_RASL_R) || (naltype >= HEVC_NAL_BLA_W_LP && naltype <= HEVC_NAL_CRA_NUT));
    } else if ((ES_H265_SM4_CBC == hls_encryptinfo->es_type) || (ES_H265_SAMPLE_SM4_CBC == hls_encryptinfo->es_type)) {
        naltype = (buffer[0] & 0x7E) >> 1;
        //section 6.2.4 in GY/T277-2019, http://www.nrta.gov.cn/art/2019/6/15/art_113_46189.html
        is_encrypted_naltype = (naltype >= 0 && naltype <= HEVC_NAL_RSV_VCL31);
    } else {
        av_log(NULL, AV_LOG_WARNING, "unknown es type  %d, it shouldn't happen here,pls check...", hls_encryptinfo->es_type);
        return -1;
    }

    if (!is_encrypted_naltype) {
        return -1;
    }

    if ((ES_H264_SAMPLE_AES == hls_encryptinfo->es_type) || (ES_H264_SAMPLE_SM4_CBC == hls_encryptinfo->es_type)
        || (ES_H265_SAMPLE_SM4_CBC == hls_encryptinfo->es_type)) {
        //10%  H264 Sample AES encrypted per 160 bytes, first 1 for leading 32 bytes, second 1 for left bytes
        //10%  H264 Sample SM4-CBC encrypted per 160 bytes, first 1 for leading 32 bytes, second 1 for left bytes
        //10%  H265 Sample SM4-CBC encrypted per 160 bytes, first 1 for leading 65 bytes, second 1 for left bytes
        clear_bytes   = (uint32_t*)av_mallocz(sizeof(uint32_t) * ((buffer_size / 160) + 1 + 1));
        encrypt_bytes = (uint32_t*)av_mallocz(sizeof(uint32_t) * ((buffer_size / 160) + 1 + 1));
    } else if ((ES_H264_SM4_CBC == hls_encryptinfo->es_type) || (ES_H265_SM4_CBC == hls_encryptinfo->es_type)) {
        //100% H264 SM4-CBC encrypted, first 1 for leading 32 bytes, second 1 for encrypted bytes, the last 1 for left bytes
        //100% H265 SM4-CBC encrypted, first 1 for leading 65 bytes, second 1 for encrypted bytes, the last 1 for left bytes
        clear_bytes   = (uint32_t*)av_mallocz(sizeof(uint32_t) * (1 + 1 + 1));
        encrypt_bytes = (uint32_t*)av_mallocz(sizeof(uint32_t) * (1 + 1 + 1));
    }

    if ((NULL == clear_bytes) || (NULL == encrypt_bytes)) {
        av_log(NULL, AV_LOG_WARNING, "clear_bytes or encrypt_bytes is NULL");
        return;
    }

    if ((ES_H265_SM4_CBC == hls_encryptinfo->es_type) || (ES_H265_SAMPLE_SM4_CBC == hls_encryptinfo->es_type)) {
        //section 6.2.4 in GY/T277-2019, http://www.nrta.gov.cn/art/2019/6/15/art_113_46189.html
        clear_bytes[clear_index++] =  min(65, tmp_nal_size);
        tmp_nal_size               -= min(65, tmp_nal_size);
    } else {
        clear_bytes[clear_index++] =  min(32, tmp_nal_size);
        tmp_nal_size               -= min(32, tmp_nal_size);
    }

    if ((ES_H264_SM4_CBC == hls_encryptinfo->es_type) || ( ES_H265_SM4_CBC == hls_encryptinfo->es_type)) {
        //section 6.2.3 in GY/T277-2019, http://www.nrta.gov.cn/art/2019/6/15/art_113_46189.html
        if (tmp_nal_size > 16) {
            while (tmp_nal_size > 0) {
                if (tmp_nal_size > 16) {
                    encrypt_bytes[encrypt_index++] = (tmp_nal_size - tmp_nal_size % 16);
                    tmp_nal_size  = tmp_nal_size % 16;
                } else {
                    encrypt_bytes[encrypt_index++] = 0;
                }

                if (tmp_nal_size > 0) {
                    clear_bytes[clear_index++]     = min(16, tmp_nal_size);
                    tmp_nal_size                  -= min(16, tmp_nal_size);
                }
            }

            if (encrypt_index < clear_index) {
                encrypt_bytes[encrypt_index++] = 0;
            }

        } else {
            clear_bytes[clear_index] = clear_bytes[clear_index] + tmp_nal_size;
            encrypt_bytes[encrypt_index++] = 0;
        }
        goto assemble_done;
    }

    /*
    * https://developer.apple.com/library/content/documentation/AudioVideo/Conceptual/HLS_Sample_Encryption/Encryption/Encryption.html
    *
    Encrypted_nal_unit () {

        nal_unit_type_byte                // 1 byte

        unencrypted_leader                // 31 bytes

        while (bytes_remaining() > 0) {

            if (bytes_remaining() > 16) {

                encrypted_block           // 16 bytes

            }

            unencrypted_block             // MIN(144, bytes_remaining()) bytes

        }

    }

    and
        section 6.2.3 in GY/T277-2019, http://www.nrta.gov.cn/art/2019/6/15/art_113_46189.html
    */
    if (tmp_nal_size > 16) {
        while (tmp_nal_size > 0) {
            if (tmp_nal_size > 16) {
                encrypt_bytes[encrypt_index++] = 16;
                tmp_nal_size -= 16;
            } else {
                encrypt_bytes[encrypt_index++] = 0;
            }

            if (tmp_nal_size > 0) {
                clear_bytes[clear_index++] =  min(144, tmp_nal_size);
                tmp_nal_size              -= min(144, tmp_nal_size);
            }
        }

        if (encrypt_index < clear_index) {
            encrypt_bytes[encrypt_index++] = 0;
        }
    } else {
        clear_bytes[clear_index] = clear_bytes[clear_index] + tmp_nal_size;
        encrypt_bytes[encrypt_index++] = 0;
    }

assemble_done:
    num_samples = clear_index;

    DrmBufferInfo drm_bufferinfo = { 0 };
    drm_bufferinfo.num_cleardata     = clear_bytes;
    drm_bufferinfo.num_encrypteddata = encrypt_bytes;
    drm_bufferinfo.num_subsamples    = num_samples;

    pthread_mutex_lock(&ad->lock_decryptor);
    if (ES_H264_SAMPLE_AES == ad->es_type) {
        if (ad->encrypt_level == DRM_CRYPTO_ENCRYPT_ES_BASED) {
            result =  hlsdecryptor_decrypt_esbase(ad, buffer, buffer_size, &drm_bufferinfo);
        } else if (ad->encrypt_level == DRM_CRYPTO_ENCRYPT_CONTAINER_BASED) {
            result =  hlsdecryptor_decrypt_containerbase(ad, buffer, pbuffer_size);
        } else {
            result = -1;
        }
    } else if ((ES_H264_SAMPLE_SM4_CBC == ad->es_type) || (ES_H265_SAMPLE_SM4_CBC == ad->es_type)) {
        //not working at the moment
        result = hlsdecryptor_samplesm4cbc_decrypt(ad, buffer, buffer_size, &drm_bufferinfo);
    } else if ((ES_H264_SM4_CBC == ad->es_type) || ( ES_H265_SM4_CBC == ad->es_type)) {
        result = hlsdecryptor_sm4cbc_decrypt(ad, buffer, buffer_size, &drm_bufferinfo);
    }
    pthread_mutex_unlock(&ad->lock_decryptor);

cleanup:
    av_freep(&encrypt_bytes);
    av_freep(&clear_bytes);

    return result;
}


//following are public functions
//all public   function's name: hls_decryptor_xxx
//all internal function's name: hlsdecryptor_xxx
void hls_decryptor_strip03(uint8_t *data, int *size)
{
    uint8_t *p = data;
    uint8_t *end = data + *size;

    while (( end - p ) > 3) {
        if ( p[0] == 0x0 && p[1] == 0x0 && p[2] == 3 ) {
            memmove( p + 2, p + 3, (end - (p + 3)) );
            *size -= 1;
            p     += 2;
            end   -= 1;
        }
        else {
            p++;
        }
    }
}

HLSDecryptor *hls_decryptor_init2(AVCodecParserContext *apc, ESType es_type)
{
    HLSDecryptor *hls_decryptor = NULL;

    av_assert0(NULL != apc);

    if (apc->hls_encryptinfo->is_encrypted) {
        DrmCryptoInfo crypto_info;
        DrmCryptoMode crypto_mode     = CRYPTO_MODE_NONE;
        apc->hls_encryptinfo->es_type = ES_UNKNOWN;

        if (ES_H264 == es_type) {
            if (0 == strcmp(apc->hls_encryptinfo->encryption_method, "AES-128")) {
                apc->hls_encryptinfo->es_type = ES_H264;
            } else if (0 == strcmp(apc->hls_encryptinfo->encryption_method, "SAMPLE-AES")) {
                apc->hls_encryptinfo->es_type = ES_H264_SAMPLE_AES;
            } else if (0 == strcmp(apc->hls_encryptinfo->encryption_method, "SAMPLE-SM4-CBC")) {
                apc->hls_encryptinfo->es_type = ES_H264_SAMPLE_SM4_CBC;
            } else if (0 == strcmp(apc->hls_encryptinfo->encryption_method, "SM4-CBC")) {
                apc->hls_encryptinfo->es_type = ES_H264_SM4_CBC;
            } else {
                av_log(apc, AV_LOG_WARNING, "unknown encryption_method %s", apc->hls_encryptinfo->encryption_method);
                return NULL;
            }
        } else if (ES_H265 == es_type) {
            if (0 == strcmp(apc->hls_encryptinfo->encryption_method, "AES-128")) {
                apc->hls_encryptinfo->es_type = ES_H265;
            } else if (0 == strcmp(apc->hls_encryptinfo->encryption_method, "SAMPLE-AES")) {
                apc->hls_encryptinfo->es_type = ES_H265_SAMPLE_AES;
            } else if (0 == strcmp(apc->hls_encryptinfo->encryption_method, "SAMPLE-SM4-CBC")) {
                apc->hls_encryptinfo->es_type = ES_H265_SAMPLE_SM4_CBC;
            } else if (0 == strcmp(apc->hls_encryptinfo->encryption_method, "SM4-CBC")) {
                apc->hls_encryptinfo->es_type = ES_H265_SM4_CBC;
            } else {
                av_log(apc, AV_LOG_WARNING, "unknown encryption_method %s", apc->hls_encryptinfo->encryption_method);
                return NULL;
            }
        } else {
            av_log(apc, AV_LOG_WARNING, "invalid es_type %d, only ES_H264 or ES_H265 supported", es_type);
            return NULL;
        }

        if ((ES_H264_SAMPLE_AES == apc->hls_encryptinfo->es_type) || (ES_H265_SAMPLE_AES == apc->hls_encryptinfo->es_type))
            crypto_mode     = CRYPTO_MODE_AES_CBC;
        else if ((ES_H264_SAMPLE_SM4_CBC == apc->hls_encryptinfo->es_type) || (ES_H265_SAMPLE_SM4_CBC == apc->hls_encryptinfo->es_type))
            crypto_mode     = CRYPTO_MODE_SM4_CBC;
        else if ((ES_H264_SM4_CBC == apc->hls_encryptinfo->es_type) || (ES_H265_SM4_CBC == apc->hls_encryptinfo->es_type))
            crypto_mode     = CRYPTO_MODE_SM4_CBC;

        hls_decryptor = hls_decryptor_init();
        if (NULL == hls_decryptor) {
            av_log(apc, AV_LOG_WARNING, "HLSDecryptor_init failed");
            return NULL;
        }
        hls_decryptor->apc    = apc;

        crypto_info.value     = &crypto_mode;
        crypto_info.value_size = sizeof(crypto_mode);
        hls_decryptor->setCryptoInfo(hls_decryptor, DRM_CRYPTO_CRYPTOMODE, &crypto_info);

        crypto_info.value = &(apc->hls_encryptinfo->es_type);
        crypto_info.value_size = sizeof(apc->hls_encryptinfo->es_type);
        hls_decryptor->setCryptoInfo(hls_decryptor, DRM_CRYPTO_ESMODE, &crypto_info);

        crypto_info.value = apc->hls_encryptinfo->encryption_key;
        crypto_info.value_size = sizeof(apc->hls_encryptinfo->encryption_key) / sizeof(uint8_t);
        hls_decryptor->setCryptoInfo(hls_decryptor, DRM_CRYPTO_KEY, &crypto_info);

        crypto_info.value = apc->hls_encryptinfo->encryption_iv;
        crypto_info.value_size = sizeof(apc->hls_encryptinfo->encryption_iv) / sizeof(uint8_t);
        hls_decryptor->setCryptoInfo(hls_decryptor, DRM_CRYPTO_IV, &crypto_info);

        return hls_decryptor;
    }

    return NULL;
}

void hls_decryptor_destroy(HLSDecryptor *ad)
{
    if (NULL == ad)
        return;

    pthread_mutex_destroy(&ad->lock_decryptor);
    av_freep(&ad);
}

HLSDecryptor *hls_decryptor_init()
{
    HLSDecryptor *hls_decryptor = av_mallocz(sizeof(HLSDecryptor));
    if (NULL == hls_decryptor) {
       return NULL;
    }

    hls_decryptor->encrypt_level  = DRM_CRYPTO_ENCRYPT_ES_BASED;
    hls_decryptor->need_depadding = 1;
    hls_decryptor->crypto_mode    = CRYPTO_MODE_NONE;
    pthread_mutex_init(&hls_decryptor->lock_decryptor, NULL);

    hls_decryptor->getCryptoInfo  = hlsdecryptor_get_cryptoinfo;
    hls_decryptor->setCryptoInfo  = hlsdecryptor_set_cryptoinfo;
    hls_decryptor->decrypt        = hlsdecryptor_decrypt;

    return hls_decryptor;
}
