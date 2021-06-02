/*
 * H.26L/H.264/AVC/JVT/14496-10/... parser
 * Copyright (c) 2003 Michael Niedermayer <michaelni@gmx.at>
 *
 * Copyright (c) 2021 Zhou Weiguo <zhouwg2000@gmail.com> add support with HLS H264 Sample AES, HLS H264 Sample China-SM4 CBC, HLS H264 China-SM4 CBC
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

/**
 * @file
 * H.264 / AVC / MPEG-4 part10 parser.
 * @author Michael Niedermayer <michaelni@gmx.at>
 */

#define UNCHECKED_BITSTREAM_READER 1

#include <assert.h>
#include <stdint.h>

#include "libavutil/avutil.h"
#include "libavutil/error.h"
#include "libavutil/log.h"
#include "libavutil/mem.h"
#include "libavutil/pixfmt.h"
#include "libavformat/internal.h"

#include "avcodec.h"
#include "get_bits.h"
#include "golomb.h"
#include "h264.h"
#include "h264_sei.h"
#include "h264_ps.h"
#include "h264data.h"
#include "internal.h"
#include "mpegutils.h"
#include "parser.h"

#include "hevc.h"
#include "libavutil/hlsencryptinfo.h"
#include "libavutil/hlsdecryptor.h"

typedef struct H264ParseContext {
    ParseContext pc;
    H264ParamSets ps;
    H264DSPContext h264dsp;
    H264POCContext poc;
    H264SEIContext sei;
    int is_avc;
    int nal_length_size;
    int got_first;
    int picture_structure;
    uint8_t parse_history[6];
    int parse_history_count;
    int parse_last_mb;
    int64_t reference_dts;
    int last_frame_num, last_picture_structure;

    int is_clear;
    esMode es_mode;
    HLSDecryptor *hls_decryptor;
    struct key_info *hls_encryptinfo;
} H264ParseContext;


#define MAX_DUMP_COUNTS  8

static int h264_find_frame_end(H264ParseContext *p, const uint8_t *buf,
                               int buf_size, void *logctx)
{
    int i, j;
    uint32_t state;
    ParseContext *pc = &p->pc;

    int next_avc = p->is_avc ? 0 : buf_size;
//    mb_addr= pc->mb_addr - 1;
    state = pc->state;
    if (state > 13)
        state = 7;

    if (p->is_avc && !p->nal_length_size)
        av_log(logctx, AV_LOG_ERROR, "AVC-parser: nal length size invalid\n");

    for (i = 0; i < buf_size; i++) {
        if (i >= next_avc) {
            int nalsize = 0;
            i = next_avc;
            for (j = 0; j < p->nal_length_size; j++)
                nalsize = (nalsize << 8) | buf[i++];
            if (nalsize <= 0 || nalsize > buf_size - i) {
                av_log(logctx, AV_LOG_ERROR, "AVC-parser: nal size %d remaining %d\n", nalsize, buf_size - i);
                return buf_size;
            }
            next_avc = i + nalsize;
            state    = 5;
        }

        if (state == 7) {
            i += p->h264dsp.startcode_find_candidate(buf + i, next_avc - i);
            if (i < next_avc)
                state = 2;
        } else if (state <= 2) {
            if (buf[i] == 1)
                state ^= 5;            // 2->7, 1->4, 0->5
            else if (buf[i])
                state = 7;
            else
                state >>= 1;           // 2->1, 1->0, 0->0
        } else if (state <= 5) {
            int nalu_type = buf[i] & 0x1F;
            if (nalu_type == H264_NAL_SEI || nalu_type == H264_NAL_SPS ||
                nalu_type == H264_NAL_PPS || nalu_type == H264_NAL_AUD) {
                if (pc->frame_start_found) {
                    i++;
                    goto found;
                }
            } else if (nalu_type == H264_NAL_SLICE || nalu_type == H264_NAL_DPA ||
                       nalu_type == H264_NAL_IDR_SLICE) {
                state += 8;
                continue;
            }
            state = 7;
        } else {
            unsigned int mb, last_mb = p->parse_last_mb;
            GetBitContext gb;
            p->parse_history[p->parse_history_count++] = buf[i];

            init_get_bits(&gb, p->parse_history, 8*p->parse_history_count);
            mb= get_ue_golomb_long(&gb);
            if (get_bits_left(&gb) > 0 || p->parse_history_count > 5) {
                p->parse_last_mb = mb;
                if (pc->frame_start_found) {
                    if (mb <= last_mb) {
                        i -= p->parse_history_count - 1;
                        p->parse_history_count = 0;
                        goto found;
                    }
                } else
                    pc->frame_start_found = 1;
                p->parse_history_count = 0;
                state = 7;
            }
        }
    }
    pc->state = state;
    if (p->is_avc)
        return next_avc;
    return END_NOT_FOUND;

found:
    pc->state             = 7;
    pc->frame_start_found = 0;
    if (p->is_avc)
        return next_avc;
    return i - (state & 5);
}

static int scan_mmco_reset(AVCodecParserContext *s, GetBitContext *gb,
                           void *logctx)
{
    H264PredWeightTable pwt;
    int slice_type_nos = s->pict_type & 3;
    H264ParseContext *p = s->priv_data;
    int list_count, ref_count[2];


    if (p->ps.pps->redundant_pic_cnt_present)
        get_ue_golomb(gb); // redundant_pic_count

    if (slice_type_nos == AV_PICTURE_TYPE_B)
        get_bits1(gb); // direct_spatial_mv_pred

    if (ff_h264_parse_ref_count(&list_count, ref_count, gb, p->ps.pps,
                                slice_type_nos, p->picture_structure, logctx) < 0)
        return AVERROR_INVALIDDATA;

    if (slice_type_nos != AV_PICTURE_TYPE_I) {
        int list;
        for (list = 0; list < list_count; list++) {
            if (get_bits1(gb)) {
                int index;
                for (index = 0; ; index++) {
                    unsigned int reordering_of_pic_nums_idc = get_ue_golomb_31(gb);

                    if (reordering_of_pic_nums_idc < 3)
                        get_ue_golomb_long(gb);
                    else if (reordering_of_pic_nums_idc > 3) {
                        av_log(logctx, AV_LOG_ERROR,
                               "illegal reordering_of_pic_nums_idc %d\n",
                               reordering_of_pic_nums_idc);
                        return AVERROR_INVALIDDATA;
                    } else
                        break;

                    if (index >= ref_count[list]) {
                        av_log(logctx, AV_LOG_ERROR,
                               "reference count %d overflow\n", index);
                        return AVERROR_INVALIDDATA;
                    }
                }
            }
        }
    }

    if ((p->ps.pps->weighted_pred && slice_type_nos == AV_PICTURE_TYPE_P) ||
        (p->ps.pps->weighted_bipred_idc == 1 && slice_type_nos == AV_PICTURE_TYPE_B))
        ff_h264_pred_weight_table(gb, p->ps.sps, ref_count, slice_type_nos,
                                  &pwt, p->picture_structure, logctx);

    if (get_bits1(gb)) { // adaptive_ref_pic_marking_mode_flag
        int i;
        for (i = 0; i < MAX_MMCO_COUNT; i++) {
            MMCOOpcode opcode = get_ue_golomb_31(gb);
            if (opcode > (unsigned) MMCO_LONG) {
                av_log(logctx, AV_LOG_ERROR,
                       "illegal memory management control operation %d\n",
                       opcode);
                return AVERROR_INVALIDDATA;
            }
            if (opcode == MMCO_END)
               return 0;
            else if (opcode == MMCO_RESET)
                return 1;

            if (opcode == MMCO_SHORT2UNUSED || opcode == MMCO_SHORT2LONG)
                get_ue_golomb_long(gb); // difference_of_pic_nums_minus1
            if (opcode == MMCO_SHORT2LONG || opcode == MMCO_LONG2UNUSED ||
                opcode == MMCO_LONG || opcode == MMCO_SET_MAX_LONG)
                get_ue_golomb_31(gb);
        }
    }

    return 0;
}

/**
 * Parse NAL units of found picture and decode some basic information.
 *
 * @param s parser context.
 * @param avctx codec context.
 * @param buf buffer with field/frame data.
 * @param buf_size size of the buffer.
 */
static inline int parse_nal_units(AVCodecParserContext *s,
                                  AVCodecContext *avctx,
                                  const uint8_t * const buf, int buf_size, int *keyframe_index, int *seiframe_index, int *keyframe_type)
{
    H264ParseContext *p = s->priv_data;
    H2645RBSP rbsp = { NULL };
    H2645NAL nal = { NULL };
    int buf_index, next_avc;
    unsigned int pps_id;
    unsigned int slice_type;
    int state = -1, got_reset = 0;
    int q264 = buf_size >=4 && !memcmp("Q264", buf, 4);
    int field_poc[2];
    int ret;

    *keyframe_type  =  0;
    *keyframe_index =  8;
    *seiframe_index =  -1;

    /* set some sane default values */
    s->pict_type         = AV_PICTURE_TYPE_I;
    s->key_frame         = 0;
    s->picture_structure = AV_PICTURE_STRUCTURE_UNKNOWN;

    ff_h264_sei_uninit(&p->sei);
    p->sei.frame_packing.arrangement_cancel_flag = -1;

    if (!buf_size)
        return 0;

    av_fast_padded_malloc(&rbsp.rbsp_buffer, &rbsp.rbsp_buffer_alloc_size, buf_size);
    if (!rbsp.rbsp_buffer)
        return AVERROR(ENOMEM);

    buf_index     = 0;
    next_avc      = p->is_avc ? 0 : buf_size;
    for (;;) {
        const SPS *sps;
        int src_length, consumed, nalsize = 0;

        if (buf_index >= next_avc) {
            nalsize = get_nalsize(p->nal_length_size, buf, buf_size, &buf_index, avctx);
            if (nalsize < 0)
                break;
            next_avc = buf_index + nalsize;
        } else {
            buf_index = find_start_code(buf, buf_size, buf_index, next_avc);
            if (buf_index >= buf_size)
                break;
            if (buf_index >= next_avc)
                continue;
        }
        src_length = next_avc - buf_index;

        state = buf[buf_index];
        if  ((state & 0x1f)  == H264_NAL_SLICE) {
            *keyframe_type = H264_NAL_SLICE;
        }
        if  ((state & 0x1f)  == H264_NAL_IDR_SLICE) {
            *keyframe_type = H264_NAL_IDR_SLICE;
        }

        switch (state & 0x1f) {
        case H264_NAL_SLICE:
        case H264_NAL_IDR_SLICE:
            // Do not walk the whole buffer just to decode slice header
            if ((state & 0x1f) == H264_NAL_IDR_SLICE || ((state >> 5) & 0x3) == 0) {
                /* IDR or disposable slice
                 * No need to decode many bytes because MMCOs shall not be present. */
                if (src_length > 60)
                    src_length = 60;
            } else {
                /* To decode up to MMCOs */
                if (src_length > 1000)
                    src_length = 1000;
            }
            *keyframe_index = buf_index;
            break;
        case H264_NAL_SEI:
            *seiframe_index = buf_index;
            *keyframe_type  = H264_NAL_SEI;
            break;
        }
        consumed = ff_h2645_extract_rbsp(buf + buf_index, src_length, &rbsp, &nal, 1);
        if (consumed < 0)
            break;

        buf_index += consumed;

        ret = init_get_bits8(&nal.gb, nal.data, nal.size);
        if (ret < 0)
            goto fail;
        get_bits1(&nal.gb);
        nal.ref_idc = get_bits(&nal.gb, 2);
        nal.type    = get_bits(&nal.gb, 5);

        switch (nal.type) {
        case H264_NAL_SPS:
            ff_h264_decode_seq_parameter_set(&nal.gb, avctx, &p->ps, 0);
            break;
        case H264_NAL_PPS:
            ff_h264_decode_picture_parameter_set(&nal.gb, avctx, &p->ps,
                                                 nal.size_bits);
            break;
        case H264_NAL_SEI:
            ff_h264_sei_decode(&p->sei, &nal.gb, &p->ps, avctx);
            break;
        case H264_NAL_IDR_SLICE:
            s->key_frame = 1;

            p->poc.prev_frame_num        = 0;
            p->poc.prev_frame_num_offset = 0;
            p->poc.prev_poc_msb          =
            p->poc.prev_poc_lsb          = 0;
        /* fall through */
        case H264_NAL_SLICE:
            get_ue_golomb_long(&nal.gb);  // skip first_mb_in_slice
            slice_type   = get_ue_golomb_31(&nal.gb);
            s->pict_type = ff_h264_golomb_to_pict_type[slice_type % 5];
            if (p->sei.recovery_point.recovery_frame_cnt >= 0) {
                /* key frame, since recovery_frame_cnt is set */
                s->key_frame = 1;
            }
            pps_id = get_ue_golomb(&nal.gb);
            if (pps_id >= MAX_PPS_COUNT) {
                av_log(avctx, AV_LOG_ERROR,
                       "pps_id %u out of range\n", pps_id);
                goto fail;
            }
            if (!p->ps.pps_list[pps_id]) {
                av_log(avctx, AV_LOG_ERROR,
                       "non-existing PPS %u referenced\n", pps_id);
                goto fail;
            }

            av_buffer_unref(&p->ps.pps_ref);
            p->ps.pps = NULL;
            p->ps.sps = NULL;
            p->ps.pps_ref = av_buffer_ref(p->ps.pps_list[pps_id]);
            if (!p->ps.pps_ref)
                goto fail;
            p->ps.pps = (const PPS*)p->ps.pps_ref->data;
            p->ps.sps = p->ps.pps->sps;
            sps       = p->ps.sps;

            // heuristic to detect non marked keyframes
            if (p->ps.sps->ref_frame_count <= 1 && p->ps.pps->ref_count[0] <= 1 && s->pict_type == AV_PICTURE_TYPE_I)
                s->key_frame = 1;

            p->poc.frame_num = get_bits(&nal.gb, sps->log2_max_frame_num);

            s->coded_width  = 16 * sps->mb_width;
            s->coded_height = 16 * sps->mb_height;
            s->width        = s->coded_width  - (sps->crop_right + sps->crop_left);
            s->height       = s->coded_height - (sps->crop_top   + sps->crop_bottom);
            if (s->width <= 0 || s->height <= 0) {
                s->width  = s->coded_width;
                s->height = s->coded_height;
            }

            switch (sps->bit_depth_luma) {
            case 9:
                if (sps->chroma_format_idc == 3)      s->format = AV_PIX_FMT_YUV444P9;
                else if (sps->chroma_format_idc == 2) s->format = AV_PIX_FMT_YUV422P9;
                else                                  s->format = AV_PIX_FMT_YUV420P9;
                break;
            case 10:
                if (sps->chroma_format_idc == 3)      s->format = AV_PIX_FMT_YUV444P10;
                else if (sps->chroma_format_idc == 2) s->format = AV_PIX_FMT_YUV422P10;
                else                                  s->format = AV_PIX_FMT_YUV420P10;
                break;
            case 8:
                if (sps->chroma_format_idc == 3)      s->format = AV_PIX_FMT_YUV444P;
                else if (sps->chroma_format_idc == 2) s->format = AV_PIX_FMT_YUV422P;
                else                                  s->format = AV_PIX_FMT_YUV420P;
                break;
            default:
                s->format = AV_PIX_FMT_NONE;
            }

            avctx->profile = ff_h264_get_profile(sps);
            avctx->level   = sps->level_idc;

            if (sps->frame_mbs_only_flag) {
                p->picture_structure = PICT_FRAME;
            } else {
                if (get_bits1(&nal.gb)) { // field_pic_flag
                    p->picture_structure = PICT_TOP_FIELD + get_bits1(&nal.gb); // bottom_field_flag
                } else {
                    p->picture_structure = PICT_FRAME;
                }
            }

            if (nal.type == H264_NAL_IDR_SLICE)
                get_ue_golomb_long(&nal.gb); /* idr_pic_id */
            if (sps->poc_type == 0) {
                p->poc.poc_lsb = get_bits(&nal.gb, sps->log2_max_poc_lsb);

                if (p->ps.pps->pic_order_present == 1 &&
                    p->picture_structure == PICT_FRAME)
                    p->poc.delta_poc_bottom = get_se_golomb(&nal.gb);
            }

            if (sps->poc_type == 1 &&
                !sps->delta_pic_order_always_zero_flag) {
                p->poc.delta_poc[0] = get_se_golomb(&nal.gb);

                if (p->ps.pps->pic_order_present == 1 &&
                    p->picture_structure == PICT_FRAME)
                    p->poc.delta_poc[1] = get_se_golomb(&nal.gb);
            }

            /* Decode POC of this picture.
             * The prev_ values needed for decoding POC of the next picture are not set here. */
            field_poc[0] = field_poc[1] = INT_MAX;
            ret = ff_h264_init_poc(field_poc, &s->output_picture_number, sps,
                             &p->poc, p->picture_structure, nal.ref_idc);
            if (ret < 0)
                goto fail;

            /* Continue parsing to check if MMCO_RESET is present.
             * FIXME: MMCO_RESET could appear in non-first slice.
             *        Maybe, we should parse all undisposable non-IDR slice of this
             *        picture until encountering MMCO_RESET in a slice of it. */
            if (nal.ref_idc && nal.type != H264_NAL_IDR_SLICE) {
                got_reset = scan_mmco_reset(s, &nal.gb, avctx);
                if (got_reset < 0)
                    goto fail;
            }

            /* Set up the prev_ values for decoding POC of the next picture. */
            p->poc.prev_frame_num        = got_reset ? 0 : p->poc.frame_num;
            p->poc.prev_frame_num_offset = got_reset ? 0 : p->poc.frame_num_offset;
            if (nal.ref_idc != 0) {
                if (!got_reset) {
                    p->poc.prev_poc_msb = p->poc.poc_msb;
                    p->poc.prev_poc_lsb = p->poc.poc_lsb;
                } else {
                    p->poc.prev_poc_msb = 0;
                    p->poc.prev_poc_lsb =
                        p->picture_structure == PICT_BOTTOM_FIELD ? 0 : field_poc[0];
                }
            }

            if (p->sei.picture_timing.present) {
                ret = ff_h264_sei_process_picture_timing(&p->sei.picture_timing,
                                                         sps, avctx);
                if (ret < 0) {
                    av_log(avctx, AV_LOG_ERROR, "Error processing the picture timing SEI\n");
                    p->sei.picture_timing.present = 0;
                }
            }

            if (sps->pic_struct_present_flag && p->sei.picture_timing.present) {
                switch (p->sei.picture_timing.pic_struct) {
                case H264_SEI_PIC_STRUCT_TOP_FIELD:
                case H264_SEI_PIC_STRUCT_BOTTOM_FIELD:
                    s->repeat_pict = 0;
                    break;
                case H264_SEI_PIC_STRUCT_FRAME:
                case H264_SEI_PIC_STRUCT_TOP_BOTTOM:
                case H264_SEI_PIC_STRUCT_BOTTOM_TOP:
                    s->repeat_pict = 1;
                    break;
                case H264_SEI_PIC_STRUCT_TOP_BOTTOM_TOP:
                case H264_SEI_PIC_STRUCT_BOTTOM_TOP_BOTTOM:
                    s->repeat_pict = 2;
                    break;
                case H264_SEI_PIC_STRUCT_FRAME_DOUBLING:
                    s->repeat_pict = 3;
                    break;
                case H264_SEI_PIC_STRUCT_FRAME_TRIPLING:
                    s->repeat_pict = 5;
                    break;
                default:
                    s->repeat_pict = p->picture_structure == PICT_FRAME ? 1 : 0;
                    break;
                }
            } else {
                s->repeat_pict = p->picture_structure == PICT_FRAME ? 1 : 0;
            }

            if (p->picture_structure == PICT_FRAME) {
                s->picture_structure = AV_PICTURE_STRUCTURE_FRAME;
                if (sps->pic_struct_present_flag && p->sei.picture_timing.present) {
                    switch (p->sei.picture_timing.pic_struct) {
                    case H264_SEI_PIC_STRUCT_TOP_BOTTOM:
                    case H264_SEI_PIC_STRUCT_TOP_BOTTOM_TOP:
                        s->field_order = AV_FIELD_TT;
                        break;
                    case H264_SEI_PIC_STRUCT_BOTTOM_TOP:
                    case H264_SEI_PIC_STRUCT_BOTTOM_TOP_BOTTOM:
                        s->field_order = AV_FIELD_BB;
                        break;
                    default:
                        s->field_order = AV_FIELD_PROGRESSIVE;
                        break;
                    }
                } else {
                    if (field_poc[0] < field_poc[1])
                        s->field_order = AV_FIELD_TT;
                    else if (field_poc[0] > field_poc[1])
                        s->field_order = AV_FIELD_BB;
                    else
                        s->field_order = AV_FIELD_PROGRESSIVE;
                }
            } else {
                if (p->picture_structure == PICT_TOP_FIELD)
                    s->picture_structure = AV_PICTURE_STRUCTURE_TOP_FIELD;
                else
                    s->picture_structure = AV_PICTURE_STRUCTURE_BOTTOM_FIELD;
                if (p->poc.frame_num == p->last_frame_num &&
                    p->last_picture_structure != AV_PICTURE_STRUCTURE_UNKNOWN &&
                    p->last_picture_structure != AV_PICTURE_STRUCTURE_FRAME &&
                    p->last_picture_structure != s->picture_structure) {
                    if (p->last_picture_structure == AV_PICTURE_STRUCTURE_TOP_FIELD)
                        s->field_order = AV_FIELD_TT;
                    else
                        s->field_order = AV_FIELD_BB;
                } else {
                    s->field_order = AV_FIELD_UNKNOWN;
                }
                p->last_picture_structure = s->picture_structure;
                p->last_frame_num = p->poc.frame_num;
            }

            av_freep(&rbsp.rbsp_buffer);
            return 0; /* no need to evaluate the rest */
        }
    }
    if (q264) {
        av_freep(&rbsp.rbsp_buffer);
        return 0;
    }
    /* didn't find a picture! */
    av_log(avctx, AV_LOG_ERROR, "missing picture in access unit with size %d\n", buf_size);
fail:
    av_freep(&rbsp.rbsp_buffer);
    return -1;
}

static void strip03(uint8_t *data, int *size )
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

/**
* @param pc    H264 parser context
* @param buf   stripped encrypted IDR/Slice data, beginning with NALU type bytes
* @param size  size of encrypted data
*/
#define min(a, b) ((a) < (b) ? (a) : (b))
#define bool uint8_t
#define true 1
#define false 0

static void decrypt_nalu(H264ParseContext *pc, uint8_t *buf, int size)
{
    uint32_t *clear_bytes   = NULL;
    uint32_t *encrypt_bytes = NULL;

    uint32_t index          = 0;
    uint32_t clear_index    = 0;
    uint32_t encrypt_index  = 0;
    uint32_t num_samples    = 0;
    uint32_t tmp_nal_size = size;

    bool     is_encrypted_naltype = 0;
    int8_t   naltype = -1;

    if ((NULL == buf) || ( size <= 0))
        return;

    if ((pc->es_mode == ES_H264_SAMPLE_AES) || (pc->es_mode == ES_H264_SM4_CBC)|| (pc->es_mode == ES_H264_SAMPLE_SM4_CBC)) {
        naltype = buf[0] & 0x1f;
        is_encrypted_naltype = true;
        bool SEI = (naltype == 6);
        if (SEI) {
            is_encrypted_naltype = false;
        }
        is_encrypted_naltype = (naltype == H264_NAL_SLICE || naltype == H264_NAL_IDR_SLICE);

    } else if ((pc->es_mode == ES_H265_SAMPLE_AES) || (pc->es_mode == ES_H265_SM4_CBC) || (pc->es_mode == ES_H265_SAMPLE_SM4_CBC)) {
        naltype = (buf[0] & 0x7E) >> 1;
        is_encrypted_naltype = true;
        bool SEI = (naltype == HEVC_NAL_SEI_PREFIX || naltype == HEVC_NAL_SEI_SUFFIX);
        if (SEI) {
            is_encrypted_naltype = false;
        }
        is_encrypted_naltype = ((naltype >= 0 && naltype <= HEVC_NAL_RASL_R) || (naltype >= HEVC_NAL_BLA_W_LP && naltype <= HEVC_NAL_CRA_NUT));
    } else {
        av_log(pc, AV_LOG_WARNING, "unknown es mode  %d, it shouldn't happen here,pls check...", pc->es_mode);
        return;
    }

    if (!is_encrypted_naltype) {
        return;
    }

    if ((ES_H264_SAMPLE_AES == pc->es_mode) || (ES_H264_SAMPLE_SM4_CBC == pc->es_mode)) {
        //10%  H264 Sample AES encrypted per 160 bytes, first 1 for leading 32 bytes, second 1 for left bytes
        //10%  H264 Sample SM4-CBC encrypted per 160 bytes, first 1 for leading 32 bytes, second 1 for left bytes
        clear_bytes   = (uint32_t*)av_mallocz(sizeof(uint32_t) * ((size / 160) + 1 + 1));
        encrypt_bytes = (uint32_t*)av_mallocz(sizeof(uint32_t) * ((size / 160) + 1 + 1));
    } else if (ES_H264_SM4_CBC == pc->es_mode) {
        //100% H264 SM4-CBC encrypted, first 1 for leading 32 bytes, second 1 for encrypted bytes, the last 1 for left bytes

        clear_bytes   = (uint32_t*)av_mallocz(sizeof(uint32_t) * (1 + 1 + 1));
        encrypt_bytes = (uint32_t*)av_mallocz(sizeof(uint32_t) * (1 + 1 + 1));
    }

    if ((NULL == clear_bytes) || (NULL == encrypt_bytes)) {
        av_log(pc, AV_LOG_WARNING, "clear_bytes or encrypt_bytes is NULL");
        return;
    }


    clear_bytes[clear_index++] =  min(32, tmp_nal_size);
    tmp_nal_size               -= min(32, tmp_nal_size);

    if (pc->es_mode == ES_H264_SM4_CBC) {
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
                    clear_bytes[clear_index++]     =  min(16, tmp_nal_size);
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

    DrmBufferInfo bufferInfo = { 0 };
    bufferInfo.numBytesOfClearData     = clear_bytes;
    bufferInfo.numBytesOfEncryptedData = encrypt_bytes;
    bufferInfo.numSubSamples           = num_samples;
    pc->hls_decryptor->decrypt(pc->hls_decryptor, buf, &size, &bufferInfo);
cleanup:
    av_freep(&encrypt_bytes);
    av_freep(&clear_bytes);
}


static int h264_parse(AVCodecParserContext *s,
                      AVCodecContext *avctx,
                      const uint8_t **poutbuf, int *poutbuf_size,
                      const uint8_t *buf, int buf_size)
{
    H264ParseContext *p = s->priv_data;
    ParseContext *pc = &p->pc;
    int next;
    int keyFrameIndex = 0;
    int keyFrameType  = 0;
    int seiFrameIndex = 0;
    int strippedSize  = 0;

    if (!p->got_first) {
        p->got_first = 1;
        if (avctx->extradata_size) {
            ff_h264_decode_extradata(avctx->extradata, avctx->extradata_size,
                                     &p->ps, &p->is_avc, &p->nal_length_size,
                                     avctx->err_recognition, avctx);
        }
    }

    if (s->flags & PARSER_FLAG_COMPLETE_FRAMES) {
        next = buf_size;

    } else {
        next = h264_find_frame_end(p, buf, buf_size, avctx);

        if (ff_combine_frame(pc, next, &buf, &buf_size) < 0) {
            *poutbuf      = NULL;
            *poutbuf_size = 0;
            return buf_size;
        }

        if (next < 0 && next != END_NOT_FOUND) {
            av_assert1(pc->last_index + next >= 0);
            h264_find_frame_end(p, &pc->buffer[pc->last_index + next], -next, avctx); // update state
        }
    }

    parse_nal_units(s, avctx, buf, buf_size, &keyFrameIndex, &seiFrameIndex, &keyFrameType);

    if (avctx->framerate.num)
        avctx->time_base = av_inv_q(av_mul_q(avctx->framerate, (AVRational){avctx->ticks_per_frame, 1}));
    if (p->sei.picture_timing.cpb_removal_delay >= 0) {
        s->dts_sync_point    = p->sei.buffering_period.present;
        s->dts_ref_dts_delta = p->sei.picture_timing.cpb_removal_delay;
        s->pts_dts_delta     = p->sei.picture_timing.dpb_output_delay;
    } else {
        s->dts_sync_point    = INT_MIN;
        s->dts_ref_dts_delta = INT_MIN;
        s->pts_dts_delta     = INT_MIN;
    }

    if (s->flags & PARSER_FLAG_ONCE) {
        s->flags &= PARSER_FLAG_COMPLETE_FRAMES;
    }

    if (s->dts_sync_point >= 0) {
        int64_t den = avctx->time_base.den * (int64_t)avctx->pkt_timebase.num;
        if (den > 0) {
            int64_t num = avctx->time_base.num * (int64_t)avctx->pkt_timebase.den;
            if (s->dts != AV_NOPTS_VALUE) {
                // got DTS from the stream, update reference timestamp
                p->reference_dts = s->dts - av_rescale(s->dts_ref_dts_delta, num, den);
            } else if (p->reference_dts != AV_NOPTS_VALUE) {
                // compute DTS based on reference timestamp
                s->dts = p->reference_dts + av_rescale(s->dts_ref_dts_delta, num, den);
            }

            if (p->reference_dts != AV_NOPTS_VALUE && s->pts == AV_NOPTS_VALUE)
                s->pts = s->dts + av_rescale(s->pts_dts_delta, num, den);

            if (s->dts_sync_point > 0)
                p->reference_dts = s->dts; // new reference
        }
    }


    av_assert0(pc->buffer != NULL);

    if ((p->es_mode == ES_H264_SAMPLE_AES)
     || (p->es_mode == ES_H264_SAMPLE_SM4_CBC)
     || (p->es_mode == ES_H264_SM4_CBC)) {

        if (seiFrameIndex > 0) {
            uint8_t seiPayloadType      = 0;
            uint8_t seiPayloadLength    = 0;
            uint8_t *pSeiFrame          = (uint8_t*)buf  + seiFrameIndex;
            int      seiFrameSize       = 0;
            int      seiFrameOrgSize    = 0;
            uint8_t *pCEI               = (uint8_t*)buf  + seiFrameIndex;
            int      ceiLength          = 0;
            int      searchOffset       = 0;
            int      searchLength       = buf_size - seiFrameIndex;

            //search next NALU prefix code
            while (searchLength > 0) {
                if ((searchLength >= 3) && (pCEI[searchOffset] == 0x00) && (pCEI[searchOffset +1] == 0x00) && (pCEI[searchOffset + 2] == 0x01)) {
                    break;
                }
                if ((searchLength >= 4) && (pCEI[searchOffset] == 0x00) && (pCEI[searchOffset +1] == 0x00) && (pCEI[searchOffset + 2] == 0x00) && (pCEI[searchOffset + 3] == 0x01)) {
                    break;
                }
                searchOffset++;
                searchLength--;
            }
            seiFrameSize    = searchOffset;
            seiFrameOrgSize = searchOffset;
            ceiLength       = searchOffset;
            //I think strip03 is not required for NAL_SEI
            strip03(pSeiFrame, &seiFrameSize);
            av_assert0((seiFrameOrgSize - seiFrameSize) == 0);

            //skip nalu type byte
            pCEI++;
            ceiLength -= 1;

            seiPayloadType      = pSeiFrame[1];
            seiPayloadLength    = pSeiFrame[2];

            //skip payload type byte and payload length byte
            pCEI      += 2;
            ceiLength -= 2;

            if (seiFrameSize >= 8) {
                //CEI UUID defined in section 6.2.3 in GY/T277-2019, http://www.nrta.gov.cn/art/2019/6/15/art_113_46189.html
                uint8_t CEI_UUID[CEI_UUID_LENGTH] = {0x70,0xC1,0xDB,0x9F,0x66,0xAE,0x41,0x27,0xBF,0xC0,0xBB,0x19,0x81,0x69,0x4B,0x66};
                if (0 == memcmp(pSeiFrame + 3, CEI_UUID, CEI_UUID_LENGTH)) {
                    uint8_t encryptionFlag;
                    uint8_t nextKeyidFlag;
                    int     ceiOffset  = 0;
                    int     ivLength   = 0;
                    uint8_t iv[KEY_LENGTH_BYTES];
                    uint8_t nextKeyId[KEY_LENGTH_BYTES];

                    //skip CEI UUID
                    pCEI      += CEI_UUID_LENGTH;
                    ceiLength -= CEI_UUID_LENGTH;

                    //ok, we got full CEI, parse it according to section 6.2.1 in GY/T277-2019, http://www.nrta.gov.cn/art/2019/6/15/art_113_46189.html
                    encryptionFlag = (pCEI[ceiOffset] >> 7) & 0x1;
                    nextKeyidFlag  = (pCEI[ceiOffset] >> 6) & 0x1;
                    ceiOffset++;
                    ceiLength--;
                    if (encryptionFlag) {
                        memcpy(p->hls_encryptinfo->encryptionKeyId, pCEI + ceiOffset, KEY_LENGTH_BYTES);
                        ff_data_to_hex(p->hls_encryptinfo->encryptionKeyIdString, pCEI + ceiOffset, KEY_LENGTH_BYTES, 1);
                        ceiOffset += KEY_LENGTH_BYTES;
                        ceiLength += KEY_LENGTH_BYTES;
                    }
                    if (nextKeyidFlag) {
                        memcpy(nextKeyId, pCEI + ceiOffset, KEY_LENGTH_BYTES);
                        ceiOffset += KEY_LENGTH_BYTES;
                        ceiLength += KEY_LENGTH_BYTES;
                    }
                    ivLength = pCEI[ceiOffset];
                    ceiOffset++;
                    ceiLength--;
                    memcpy(iv, pCEI + ceiOffset, IV_LENGTH_BYTES);
                    av_assert0(0 == memcmp(iv, p->hls_encryptinfo->encryptionIv, IV_LENGTH_BYTES));
                    ceiOffset += KEY_LENGTH_BYTES;
                    ceiLength += KEY_LENGTH_BYTES;
                }
            }
        }

        uint8_t *pKeyFrame      = (uint8_t*)buf + keyFrameIndex;
        int     keyFrameSize    = buf_size - keyFrameIndex;
        int     keyFrameOrgSize = keyFrameSize;
        strip03(pKeyFrame, &keyFrameSize);
        strippedSize = keyFrameOrgSize - keyFrameSize;
        av_assert0(strippedSize >= 0);
        decrypt_nalu(p, pKeyFrame, keyFrameSize);
    }

    *poutbuf      = buf;
    *poutbuf_size = buf_size - strippedSize;

    return next;
}

static int h264_split(AVCodecContext *avctx,
                      const uint8_t *buf, int buf_size)
{
    uint32_t state = -1;
    int has_sps    = 0;
    int has_pps    = 0;
    const uint8_t *ptr = buf, *end = buf + buf_size;
    int nalu_type;

    while (ptr < end) {
        ptr = avpriv_find_start_code(ptr, end, &state);
        if ((state & 0xFFFFFF00) != 0x100)
            break;
        nalu_type = state & 0x1F;
        if (nalu_type == H264_NAL_SPS) {
            has_sps = 1;
        } else if (nalu_type == H264_NAL_PPS)
            has_pps = 1;
        /* else if (nalu_type == 0x01 ||
         *     nalu_type == 0x02 ||
         *     nalu_type == 0x05) {
         *  }
         */
        else if ((nalu_type != H264_NAL_SEI || has_pps) &&
                  nalu_type != H264_NAL_AUD && nalu_type != H264_NAL_SPS_EXT &&
                  nalu_type != 0x0f) {
            if (has_sps) {
                while (ptr - 4 > buf && ptr[-5] == 0)
                    ptr--;
                return ptr - 4 - buf;
            }
        }
    }

    return 0;
}

static void h264_close(AVCodecParserContext *s)
{
    H264ParseContext *p = s->priv_data;
    ParseContext *pc = &p->pc;

    av_freep(&pc->buffer);
    HLSDecryptor_destroy(p->hls_decryptor);

    ff_h264_sei_uninit(&p->sei);
    ff_h264_ps_uninit(&p->ps);
}

static av_cold int init(AVCodecParserContext *s)
{
    H264ParseContext *p = s->priv_data;

    p->reference_dts  = AV_NOPTS_VALUE;
    p->last_frame_num = INT_MAX;
    p->is_clear       = 1;
    p->es_mode        = ES_UNKNOWN;
    ff_h264dsp_init(&p->h264dsp, 8, 1);

    if (s->hls_encryptinfo) {
        dump_key_info(s->hls_encryptinfo);
        p->hls_encryptinfo = s->hls_encryptinfo;
        if (s->hls_encryptinfo->isEncrypted) {
            DrmCryptoInfo cryptoInfo;
            uint32_t cryptoMode     = CRYPTO_MODE_NONE;

            p->is_clear = 0;
            p->hls_decryptor = HLSDecryptor_init();
            if (NULL == p->hls_decryptor) {
                av_log(s, AV_LOG_WARNING, "HLSDecryptor_init failed");
                return 0;
            }

            if (0 == strcmp(s->hls_encryptinfo->encryptionMethod, "AES-128")) {
                p->es_mode = ES_H264;
            } else if (0 == strcmp(s->hls_encryptinfo->encryptionMethod, "SAMPLE-AES")) {
                p->es_mode = ES_H264_SAMPLE_AES;
            } else if (0 == strcmp(s->hls_encryptinfo->encryptionMethod, "SAMPLE-SM4-CBC")) {
                p->es_mode = ES_H264_SAMPLE_SM4_CBC;
            } else if (0 == strcmp(s->hls_encryptinfo->encryptionMethod, "SM4-CBC")) {
                p->es_mode = ES_H264_SM4_CBC;
            } else {
                av_log(s, AV_LOG_WARNING, "unknown encryptionMethod %s", s->hls_encryptinfo->encryptionMethod);
                return 0;
            }

            if ((ES_H264_SAMPLE_AES == p->es_mode) || (ES_H265_SAMPLE_AES == p->es_mode))
                cryptoMode     = CRYPTO_MODE_AES_CBC;
            else if ((ES_H264_SAMPLE_SM4_CBC == p->es_mode) || (ES_H265_SAMPLE_SM4_CBC == p->es_mode))
                cryptoMode     = CRYPTO_MODE_SM4_CBC;
            else if ((ES_H264_SM4_CBC == p->es_mode) || (ES_H265_SM4_CBC == p->es_mode))
                cryptoMode     = CRYPTO_MODE_SM4_CBC;

            cryptoInfo.value     = &cryptoMode;
            cryptoInfo.valueSize = sizeof(cryptoMode);
            p->hls_decryptor->setCryptoInfo(p->hls_decryptor, DRM_CRYPTO_CRYPTOMODE, &cryptoInfo);

            cryptoInfo.value = &(p->es_mode);
            cryptoInfo.valueSize = sizeof(p->es_mode);
            p->hls_decryptor->setCryptoInfo(p->hls_decryptor, DRM_CRYPTO_ESMODE, &cryptoInfo);

            cryptoInfo.value = s->hls_encryptinfo->encryptionKey;
            cryptoInfo.valueSize = sizeof(s->hls_encryptinfo->encryptionKey) / sizeof(uint8_t);
            p->hls_decryptor->setCryptoInfo(p->hls_decryptor, DRM_CRYPTO_KEY, &cryptoInfo);

            cryptoInfo.value = s->hls_encryptinfo->encryptionIv;
            cryptoInfo.valueSize = sizeof(s->hls_encryptinfo->encryptionIv) / sizeof(uint8_t);
            p->hls_decryptor->setCryptoInfo(p->hls_decryptor, DRM_CRYPTO_IV, &cryptoInfo);
        }
    }

    return 0;
}

AVCodecParser ff_h264_parser = {
    .name           = "h264 parser",
    .codec_ids      = { AV_CODEC_ID_H264, AV_CODEC_ID_H264_SAMPLE_AES },
    .priv_data_size = sizeof(H264ParseContext),
    .parser_init    = init,
    .parser_parse   = h264_parse,
    .parser_close   = h264_close,
    .split          = h264_split,
};
