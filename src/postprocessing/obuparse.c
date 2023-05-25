/*
 * Copyright (c) 2020, Derek Buitenhuis
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "obuparse.h"

/************************************
 * Bitreader functions and structs. *
 ************************************/

typedef struct _OBPBitReader {
    uint8_t *buf;
    size_t buf_size;
    size_t buf_pos;
    uint64_t bit_buffer;
    uint8_t bits_in_buf;
} _OBPBitReader;

static inline _OBPBitReader _obp_new_br(uint8_t *buf, size_t buf_size)
{
    _OBPBitReader ret = { buf, buf_size, 0, 0, 0 };
    return ret;
}

static inline uint64_t _obp_br_unchecked(_OBPBitReader *br, uint8_t n)
{
    assert(n <= 63);

    while (n > br->bits_in_buf) {
        br->bit_buffer <<= 8;
        br->bit_buffer  |= (uint64_t) br->buf[br->buf_pos];
        br->bits_in_buf += 8;
        br->buf_pos++;

        if (br->bits_in_buf > 56) {
            if (n <= br->bits_in_buf)
                break;

            if (n <= 64)
                return (_obp_br_unchecked(br, 32) << 32) | (_obp_br_unchecked(br, n - 32));
        }
    }

    br->bits_in_buf -= n;
    return (br->bit_buffer >> br->bits_in_buf) & ((((uint64_t)1) << n) - 1);
}

static inline void _obp_br_byte_alignment(_OBPBitReader *br)
{
    br->bits_in_buf -= br->bits_in_buf % 8;
}

static inline size_t _obp_br_get_pos(_OBPBitReader *br)
{
    return (br->buf_pos * 8) - ((size_t) br->bits_in_buf);
}

#if OBP_UNCHECKED_BITREADER
#define _obp_br(x, br, n) do { \
    x = _obp_br_unchecked(br, n); \
} while(0)
#else
#define _obp_br(x, br, n) do { \
    size_t bytes_needed = ((n - br->bits_in_buf) + (1<<3) - 1) >> 3; \
    if (bytes_needed > (br->buf_size - br->buf_pos)) { \
        snprintf(err->error, err->size, "Ran out of bytes in buffer."); \
        return -1; \
    } \
    x = _obp_br_unchecked(br, n); \
} while(0)
#endif

/************************************
 * Functions from AV1 specification. *
 ************************************/

static inline int _obp_leb128(uint8_t *buf, size_t size, uint64_t *value, ptrdiff_t *consumed, OBPError *err)
{
    *value       = 0;
    *consumed    = 0;

    for (uint64_t i = 0; i < 8; i++) {
        uint8_t b;

        if (((size_t) (*consumed) + 1) > size) {
            snprintf(err->error, err->size, "Buffer too short to read leb128 value.");
            return -1;
        }

        b       = buf[*consumed];
        *value |= ((uint64_t)(b & 0x7F)) << (i * 7);
        (*consumed)++;

        if ((b & 0x80) != 0x80)
            break;
    }

    return 0;
}

static inline int _obp_uvlc(_OBPBitReader *br, uint32_t *value, OBPError *err)
{
    uint32_t leading_zeroes = 0;
    while (leading_zeroes < 32) {
        int b;
        _obp_br(b, br, 1);
        if (b != 0)
            break;
        leading_zeroes++;
    }
    if (leading_zeroes == 32) {
        snprintf(err->error, err->size, "Invalid VLC.");
        return -1;
    }
    uint32_t val;
    _obp_br(val, br, leading_zeroes);
    *value = val + ((1 << leading_zeroes) - 1);
    return 0;
}

static inline int32_t _obp_get_relative_dist(int32_t a, int32_t b, OBPSequenceHeader *seq)
{
    int32_t diff, m;

    if (!seq->enable_order_hint)
        return 0;

    diff = a - b;
    m    = 1 << (seq->OrderHintBits - 1);
    diff = (diff & (m - 1)) - (diff & m);

    return diff;
}



static inline uint32_t _obp_tile_log2(uint32_t blkSize, uint32_t target)
{
    uint32_t k;
    for (k = 0; (blkSize << k) < target; k++) {
    }
    return k;
}

static inline uint32_t _obp_floor_log2(uint32_t a)
{
    uint32_t s = 0;
    uint32_t x = a;
    while (x != 0) {
        x = x >> 1;
        s++;
    }
    return s - 1;
}

static inline uint64_t _obp_le(uint8_t *buf, uint8_t n)
{
    uint64_t t = 0;
    size_t pos = 0;
    for (uint8_t i = 0; i < n; i++) {
        uint8_t byte = buf[pos];
        t += ((uint64_t)byte) << (i * 8);
        pos++;
    }
    return t;
}

static inline int _obp_ns(_OBPBitReader *br, uint32_t n, uint32_t *out, OBPError *err)
{
    uint32_t w = _obp_floor_log2(n) + 1;
    uint32_t m = (((uint32_t)1) << w) - n;
    uint32_t v;
    uint32_t extra_bit;

    assert(w - 1 <= 32);
    _obp_br(v, br, ((uint8_t)(w - 1)));
    if (v < m) {
        *out = v;
        return 0;
    }
    _obp_br(extra_bit, br, 1);
    *out = (v << 1) - m + extra_bit;
    return 0;
}

static inline int _obp_su(_OBPBitReader *br, uint32_t n, int32_t *out, OBPError *err)
{
    int32_t value;
    uint32_t signMask;

    _obp_br(value, br, n);
    signMask = ((uint32_t)1) << (n - 1);
    if (value & signMask) {
        value = value - 2 * signMask;
    }
    *out = value;
    return 0;
}

static inline int _obp_decode_subexp(_OBPBitReader *br, int32_t numSyms, uint32_t *out, OBPError *err)
{
    int32_t i  = 0;
    int32_t mk = 0;
    int32_t k  = 3;
    while (1) {
        int32_t b2 = i ? k + i - 1 : k;
        int32_t a  = 1 << b2;
        if (numSyms <= mk + 3 * a) {
            uint32_t val;
            int ret = _obp_ns(br, numSyms - mk, &val, err);
            if (ret < 0) {
                return -1;
            }
            *out = val;
            return 0;
        } else {
            int subexp_more_bits;
            _obp_br(subexp_more_bits, br, 1);
            if (subexp_more_bits) {
                i++;
                mk += a;
            } else {
                uint32_t subexp_bits;
                assert(b2 <= 255);
                _obp_br(subexp_bits, br, ((uint8_t)b2));
                *out = subexp_bits + mk;
                return 0;
            }
        }
    }
}

static inline int32_t _obps_inverse_recenter(int32_t r, uint32_t v)
{
    if (((uint64_t)v) > ((uint64_t)(2 * r))) {
        return (int32_t) v;
    } else if (v & 1) {
        return r - ((v + 1) >> 1);
    } else {
        return r + (v >> 1);
    }
}

static inline int _obp_decode_unsigned_subexp_with_ref(_OBPBitReader *br, int32_t mx, int32_t r, int16_t *out, OBPError *err) {
    uint32_t v;
    int ret = _obp_decode_subexp(br, mx, &v, err);
    if (ret < 0) {
        return -1;
    }
    if (r < 0) { /* avoid signed shift */
        if (-(-r << 1) <= mx) {
            *out = _obps_inverse_recenter(r, v);
            return 0;
        }
    }
    if ((r << 1) <= mx) {
        *out = _obps_inverse_recenter(r, v);
        return 0;
    } else {
        *out = mx - 1 - _obps_inverse_recenter(mx - 1 - r, v);
        return 0;
    }

    return 0;
}

static inline int _obp_decode_signed_subexp_with_ref(_OBPBitReader *br, int32_t low, int32_t high, int32_t r, int16_t *out, OBPError *err) {
    int16_t val;
    int ret = _obp_decode_unsigned_subexp_with_ref(br, high - low, r - low, &val, err);
    if (ret < 0) {
        return -1;
    }
    *out = val + low;
    return 0;
}

/*********************
 * Helper functions. *
 *********************/

#define _OBP_MAX(x,y) ((x) > (y) ? x : y)
#define _OBP_MIN(x,y) ((x) < (y) ? x : y)

static inline int _obp_is_valid_obu(OBPOBUType type)
{
    return type == OBP_OBU_SEQUENCE_HEADER ||
           type == OBP_OBU_TEMPORAL_DELIMITER ||
           type == OBP_OBU_FRAME_HEADER ||
           type == OBP_OBU_TILE_GROUP ||
           type == OBP_OBU_METADATA ||
           type == OBP_OBU_FRAME ||
           type == OBP_OBU_REDUNDANT_FRAME_HEADER ||
           type == OBP_OBU_TILE_LIST ||
           type == OBP_OBU_PADDING;
}

static inline int _obp_set_frame_refs(OBPFrameHeader *fh, OBPSequenceHeader *seq, OBPState *state, OBPError *err)
{
    int usedFrame[8];
    uint32_t curFrameHint, lastOrderHint, goldOrderHint, latestOrderHint, earliestOrderHint;
    int32_t ref;
    uint8_t shiftedOrderHints[8];
    const int Ref_Frame_List[7 - 2] = { 2, 3, 5, 6, 7 }; /*LAST2_FRAME, LAST3_FRAME, BWDREF_FRAME, ALTREF2_FRAME, ALTREF_FRAME */
    int32_t ref_frame_idx[8];

    for (int i = 0; i < 7; i++) {
        ref_frame_idx[i] = -1;
    }
    ref_frame_idx[1 - 1] = fh->last_frame_idx;
    ref_frame_idx[4 - 1] = fh->gold_frame_idx;
    for (int i = 0; i < 8; i++) {
        usedFrame[i] = 0;
    }
    usedFrame[fh->last_frame_idx] = 1;
    usedFrame[fh->gold_frame_idx] = 2;
    curFrameHint                  = 1 << (seq->OrderHintBits - 1);
    for (int i = 0; i < 8; i++) {
        shiftedOrderHints[i] = curFrameHint + _obp_get_relative_dist(state->RefOrderHint[i], fh->order_hint, seq);
    }
    lastOrderHint = shiftedOrderHints[fh->last_frame_idx];
    goldOrderHint = shiftedOrderHints[fh->gold_frame_idx];
    if (lastOrderHint >= curFrameHint || goldOrderHint >= curFrameHint) {
        snprintf(err->error, err->size, "(lastOrderHint >= curFrameHint || goldOrderHint >= curFrameHint) not allowed.");
        return -1;
    }
    /* find_latest_backward() */
    ref             = -1;
    latestOrderHint = 0;
    for (int i = 0; i < 8; i++) {
        uint32_t hint = shiftedOrderHints[i];
        if (!usedFrame[i] && (hint >= curFrameHint) && (ref < 0 || hint >= latestOrderHint)) {
            ref             = i;
            latestOrderHint = hint;
        }
    }
    if (ref >= 0) {
        ref_frame_idx[7 - 1] = ref;
        usedFrame[ref]       = 1;
    }
    /* find_earliest_backward() */
    ref               = -1;
    earliestOrderHint = 0;
    for (int i = 0; i < 8; i++) {
        uint32_t hint = shiftedOrderHints[i];
        if (!usedFrame[i] && (hint >= curFrameHint) && (ref < 0 || hint < earliestOrderHint)) {
            ref               = i;
            earliestOrderHint = hint;
        }
    }
    if (ref >= 0) {
        ref_frame_idx[5 - 1] = ref;
        usedFrame[ref]       = 1;
    }
    /* find_earliest_backward() */
    ref               = -1;
    earliestOrderHint = 0;
    for (int i = 0; i < 8; i++) {
        uint32_t hint = shiftedOrderHints[i];
        if (!usedFrame[i] && (hint >= curFrameHint) && (ref < 0 || hint < earliestOrderHint)) {
            ref               = i;
            earliestOrderHint = hint;
        }
    }
    if (ref >= 0) {
        ref_frame_idx[6 - 1] = ref;
        usedFrame[ref]       = 1;
    }
    for (int i = 0; i < 7 - 2; i++) {
        uint8_t refFrame = Ref_Frame_List[i];
        if (ref_frame_idx[refFrame - 1] < 0) {
            int32_t subref              = -1;
            uint32_t subLatestOrderHint = 0;
            for (int i = 0; i < 8; i++) {
                uint32_t hint = shiftedOrderHints[i];
                if (!usedFrame[i] && (hint < curFrameHint) && (ref < 0 || hint >= subLatestOrderHint)) {
                    ref                = i;
                    subLatestOrderHint = 0;
                }
            }
            ref = subref;
            if (ref >= 0) {
                ref_frame_idx[refFrame - 1] = ref;
                usedFrame[ref]              = 1;
            }
        }
    }
    ref = -1;
    for (int i = 0; i < 8; i++) {
        uint32_t hint = shiftedOrderHints[i];
        if (ref < 0 || hint < earliestOrderHint) {
            ref = i;
            earliestOrderHint = hint;
        }
    }
    for (int i = 0; i < 7; i++) {
        if (ref_frame_idx[i] < 0) {
            ref_frame_idx[i] = ref;
        }
    }
    for (int i = 0; i < 7; i++) {
        fh->ref_frame_idx[i] = ref_frame_idx[i];
    }

    return 0;
}

static inline int _obp_read_delta_q(_OBPBitReader *br, int32_t *out, OBPError *err)
{
    int delta_coded;
    _obp_br(delta_coded, br, 1);
    if (delta_coded) {
        int32_t val;
        int ret = _obp_su(br, 7, &val, err);
        if (ret < 0)
            return ret;
        *out = val;
    } else {
        *out = 1;
    }
    return 0;
}

static inline uint8_t _obp_get_qindex(int ignoreDeltaQ, int segmentId, int16_t CurrentQIndex, OBPFrameHeader *fh, int FeatureEnabled[8][8], int16_t FeatureData[8][8])
{
    if (fh->segmentation_params.segmentation_enabled && FeatureEnabled[segmentId][0]) {
        int16_t data   = FeatureData[segmentId][0];
        int32_t qindex = data + ((int32_t) fh->quantization_params.base_q_idx);
        if (ignoreDeltaQ == 0 && fh->delta_q_params.delta_q_present == 1) {
            qindex = CurrentQIndex + data;
        }
        return _OBP_MAX(0, _OBP_MIN(255, qindex));
    }

    if (ignoreDeltaQ == 0 && fh->delta_q_params.delta_q_present == 1) {
        return CurrentQIndex;
    }

    return fh->quantization_params.base_q_idx;
}

static inline int _obp_read_global_param(_OBPBitReader *br, OBPFrameHeader *fh, uint8_t type, int ref, int idx, OBPError *err)
{
    uint8_t absBits  = 12;
    uint8_t precBits = 15;
    if (idx < 2) {
        if (type == 1) {
            absBits  = 9 - !fh->allow_high_precision_mv;
            precBits = 3 - !fh->allow_high_precision_mv;
        } else {
            absBits  = 12;
            precBits = 6;
        }
    }
    int32_t precDiff = 16 - precBits;
    int32_t round    = ((idx % 3) == 2) ? (1 << 16) : 0;
    int32_t sub      = ((idx % 3) == 2) ? (1 << precBits) : 0;
    int32_t mx       = (1 << absBits);
    int32_t r        = (fh->global_motion_params.prev_gm_params[ref][idx] >> precDiff) - sub;
    int16_t val;
    int ret = _obp_decode_signed_subexp_with_ref(br, -mx, mx + 1, r, &val, err);
    if (ret < 0) {
        return -1;
    }
    if (val < 0) { /* signed shifts are bad. */
        val                                          = -val;
        fh->global_motion_params.gm_params[ref][idx] = (-(val << precDiff) + round);
    } else {
        fh->global_motion_params.gm_params[ref][idx] = (val << precDiff) + round;
    }

    return 0;
}


/*****************************
 * API functions start here. *
 *****************************/

int obp_get_next_obu(uint8_t *buf, size_t buf_size, OBPOBUType *obu_type, ptrdiff_t *offset,
                     size_t *size, int *temporal_id, int *spatial_id, OBPError *err)
{
    ptrdiff_t pos = 0;
    int obu_extension_flag;
    int obu_has_size_field;

    if (buf_size < 1) {
        snprintf(err->error, err->size, "Buffer is too small to contain an OBU.");
        return -1;
    }

    *obu_type          = (buf[pos] & 0x78) >> 3;
    obu_extension_flag = (buf[pos] & 0x04) >> 2;
    obu_has_size_field = (buf[pos] & 0x02) >> 1;
    pos++;

    if (!_obp_is_valid_obu(*obu_type)) {
        snprintf(err->error, err->size, "OBU header contains invalid OBU type: %d", *obu_type);
        return -1;
    }

    if (obu_extension_flag) {
        if (buf_size < 1) {
            snprintf(err->error, err->size, "Buffer is too small to contain an OBU extension header.");
            return -1;
        }
        *temporal_id = (buf[pos] & 0xE0) >> 5;
        *spatial_id  = (buf[pos] & 0x18) >> 3;
        pos++;
    } else {
        *temporal_id = 0;
        *spatial_id  = 0;
    }

    if (obu_has_size_field) {
        char err_buf[1024];
        uint64_t value;
        ptrdiff_t consumed;
        OBPError error = { &err_buf[0], 1024 };

        int ret      = _obp_leb128(buf + pos, buf_size - (size_t) pos, &value, &consumed, &error);
        if (ret < 0) {
            snprintf(err->error, err->size, "Failed to read OBU size: %s", &error.error[0]);
            return -1;
        }

        assert(value < UINT32_MAX);

        *offset = (ptrdiff_t) pos + consumed;
        *size   = (size_t) value;
    } else {
        *offset = (ptrdiff_t) pos;
        *size   = buf_size - (size_t) pos;
    }

    if (*size > buf_size - (size_t) offset) {
        snprintf(err->error, err->size, "Invalid OBU size: larger than remaining buffer.");
        return -1;
    }

    return 0;
}

int obp_parse_sequence_header(uint8_t *buf, size_t buf_size, OBPSequenceHeader *seq_header, OBPError *err)
{
    _OBPBitReader b   = _obp_new_br(buf, buf_size);
    _OBPBitReader *br = &b;

    _obp_br(seq_header->seq_profile, br, 3);
    _obp_br(seq_header->still_picture, br, 1);
    _obp_br(seq_header->reduced_still_picture_header, br, 1);
    if (seq_header->reduced_still_picture_header) {
        seq_header->timing_info_present_flag                     = 0;
        seq_header->decoder_model_info_present_flag              = 0;
        seq_header->initial_display_delay_present_flag           = 0;
        seq_header->operating_points_cnt_minus_1                 = 0;
        seq_header->operating_point_idc[0]                       = 0;
        seq_header->seq_level_idx[0]                             = 0;
        seq_header->seq_tier[0]                                  = 0;
        seq_header->decoder_model_present_for_this_op[0]         = 0;
        seq_header->initial_display_delay_present_for_this_op[0] = 0;
    } else {
        _obp_br(seq_header->timing_info_present_flag, br, 1);
        if (seq_header->timing_info_present_flag) {
            /* timing_info() */
            _obp_br(seq_header->timing_info.num_units_in_display_tick, br, 32);
            _obp_br(seq_header->timing_info.time_scale, br, 32);
            _obp_br(seq_header->timing_info.equal_picture_interval, br, 1);
            if (seq_header->timing_info.equal_picture_interval) {
                int ret = _obp_uvlc(br, &seq_header->timing_info.num_ticks_per_picture_minus_1, err);
                if (ret < 0)
                    return -1;
            }
            _obp_br(seq_header->decoder_model_info_present_flag, br, 1);
            if (seq_header->decoder_model_info_present_flag) {
                /* decoder_model_info() */
                _obp_br(seq_header->decoder_model_info.buffer_delay_length_minus_1, br, 5);
                _obp_br(seq_header->decoder_model_info.num_units_in_decoding_tick, br, 32);
                _obp_br(seq_header->decoder_model_info.buffer_removal_time_length_minus_1, br, 5);
                _obp_br(seq_header->decoder_model_info.frame_presentation_time_length_minus_1, br, 5);
            }
        } else {
            seq_header->decoder_model_info_present_flag = 0;
        }
        _obp_br(seq_header->initial_display_delay_present_flag, br, 1);
        _obp_br(seq_header->operating_points_cnt_minus_1, br, 5);
        for (uint8_t i = 0; i <= seq_header->operating_points_cnt_minus_1; i++) {
            _obp_br(seq_header->operating_point_idc[i], br, 12);
            _obp_br(seq_header->seq_level_idx[i], br, 5);
            if (seq_header->seq_level_idx[i] > 7) {
                _obp_br(seq_header->seq_tier[i], br, 1);
            } else {
                seq_header->seq_tier[i] = 0;
            }
            if (seq_header->decoder_model_info_present_flag) {
                _obp_br(seq_header->decoder_model_present_for_this_op[i], br, 1);
                if (seq_header->decoder_model_present_for_this_op[i]) {
                    /* operating_parameters_info() */
                    uint8_t n = seq_header->decoder_model_info.buffer_delay_length_minus_1 + 1;
                    _obp_br(seq_header->operating_parameters_info[i].decoder_buffer_delay, br, n);
                    _obp_br(seq_header->operating_parameters_info[i].encoder_buffer_delay, br, n);
                    _obp_br(seq_header->operating_parameters_info[i].low_delay_mode_flag, br, 1);
                }
            } else {
                seq_header->decoder_model_present_for_this_op[i] = 0;
            }
            if (seq_header->initial_display_delay_present_flag) {
                _obp_br(seq_header->initial_display_delay_present_for_this_op[i], br, 1);
                if (seq_header->initial_display_delay_present_for_this_op[i]) {
                    _obp_br(seq_header->initial_display_delay_minus_1[i], br, 4);
                }
            }
        }
    }
    _obp_br(seq_header->frame_width_bits_minus_1, br, 4);
    _obp_br(seq_header->frame_height_bits_minus_1, br, 4);
    _obp_br(seq_header->max_frame_width_minus_1, br, seq_header->frame_width_bits_minus_1 + 1);
    _obp_br(seq_header->max_frame_height_minus_1, br, seq_header->frame_height_bits_minus_1 + 1);
    if (seq_header->reduced_still_picture_header) {
        seq_header->frame_id_numbers_present_flag = 0;
    } else {
        _obp_br(seq_header->frame_id_numbers_present_flag, br, 1);
    }
    if (seq_header->frame_id_numbers_present_flag) {
        _obp_br(seq_header->delta_frame_id_length_minus_2, br, 4);
        _obp_br(seq_header->additional_frame_id_length_minus_1, br, 3);
    }
    _obp_br(seq_header->use_128x128_superblock, br, 1);
    _obp_br(seq_header->enable_filter_intra, br, 1);
    _obp_br(seq_header->enable_intra_edge_filter, br, 1);
    if (seq_header->reduced_still_picture_header) {
        seq_header->enable_interintra_compound     = 0;
        seq_header->enable_masked_compound         = 0;
        seq_header->enable_warped_motion           = 0;
        seq_header->enable_dual_filter             = 0;
        seq_header->enable_order_hint              = 0;
        seq_header->enable_jnt_comp                = 0;
        seq_header->enable_ref_frame_mvs           = 0;
        seq_header->seq_force_screen_content_tools = 2; /* SELECT_SCREEN_CONTENT_TOOLS */
        seq_header->seq_force_integer_mv           = 2; /* SELECT_INTEGER_MV */
        seq_header->OrderHintBits                  = 0;
    } else {
        _obp_br(seq_header->enable_interintra_compound, br, 1);
        _obp_br(seq_header->enable_masked_compound, br, 1);
        _obp_br(seq_header->enable_warped_motion, br, 1);
        _obp_br(seq_header->enable_dual_filter, br, 1);
        _obp_br(seq_header->enable_order_hint, br, 1);
        if (seq_header->enable_order_hint) {
            _obp_br(seq_header->enable_jnt_comp, br, 1);
            _obp_br(seq_header->enable_ref_frame_mvs, br, 1);
        } else {
            seq_header->enable_jnt_comp = 0;
            seq_header->enable_ref_frame_mvs = 0;
        }
        _obp_br(seq_header->seq_choose_screen_content_tools, br, 1);
        if (seq_header->seq_choose_screen_content_tools) {
            seq_header->seq_force_screen_content_tools = 2; /* SELECT_SCREEN_CONTENT_TOOLS */
        } else {
            _obp_br(seq_header->seq_force_screen_content_tools, br, 1);
        }
        if (seq_header->seq_force_screen_content_tools > 0) {
            _obp_br(seq_header->seq_choose_integer_mv, br, 1);
            if (seq_header->seq_choose_integer_mv) {
                seq_header->seq_force_integer_mv = 2; /* SELECT_INTEGER_MV */
            } else {
                _obp_br(seq_header->seq_force_integer_mv, br, 1);
            }
        } else {
            seq_header->seq_force_integer_mv = 2; /* SELECT_INTEGER_MV */
        }
        if (seq_header->enable_order_hint) {
            _obp_br(seq_header->order_hint_bits_minus_1, br, 3);
            seq_header->OrderHintBits = seq_header->order_hint_bits_minus_1 + 1;
        } else {
            seq_header->OrderHintBits = 0;
        }
    }
    _obp_br(seq_header->enable_superres, br, 1);
    _obp_br(seq_header->enable_cdef, br, 1);
    _obp_br(seq_header->enable_restoration, br, 1);
    /* color_config() */
    _obp_br(seq_header->color_config.high_bitdepth, br, 1);
    if (seq_header->seq_profile == 2 && seq_header->color_config.high_bitdepth) {
        _obp_br(seq_header->color_config.twelve_bit, br, 1);
        seq_header->color_config.BitDepth = seq_header->color_config.twelve_bit ? 12 : 10;
    } else {
        seq_header->color_config.BitDepth = seq_header->color_config.high_bitdepth ? 10 : 8;
    }
    if (seq_header->seq_profile == 1) {
        seq_header->color_config.mono_chrome = 0;
    } else {
        _obp_br(seq_header->color_config.mono_chrome, br, 1);
    }
    seq_header->color_config.NumPlanes = seq_header->color_config.mono_chrome ? 1 : 3;
    _obp_br(seq_header->color_config.color_description_present_flag, br, 1);
    if (seq_header->color_config.color_description_present_flag) {
        _obp_br(seq_header->color_config.color_primaries, br, 8);
        _obp_br(seq_header->color_config.transfer_characteristics, br, 8);
        _obp_br(seq_header->color_config.matrix_coefficients, br, 8);
    } else {
        seq_header->color_config.color_primaries          = OBP_CP_UNSPECIFIED;
        seq_header->color_config.transfer_characteristics = OBP_TC_UNSPECIFIED;
        seq_header->color_config.matrix_coefficients      = OBP_MC_UNSPECIFIED;
    }
    if (seq_header->color_config.mono_chrome) {
        _obp_br(seq_header->color_config.color_range, br, 1);
        seq_header->color_config.subsampling_x          = 1;
        seq_header->color_config.subsampling_y          = 1;
        seq_header->color_config.chroma_sample_position = OBP_CSP_UNKNOWN;
        seq_header->color_config.separate_uv_delta_q    = 0;
        goto color_done;
    } else if (seq_header->color_config.color_primaries == OBP_CP_BT_709 &&
               seq_header->color_config.transfer_characteristics == OBP_TC_SRGB &&
               seq_header->color_config.matrix_coefficients == OBP_MC_IDENTITY) {
        seq_header->color_config.color_range = 1;
        seq_header->color_config.subsampling_x = 0;
        seq_header->color_config.subsampling_y = 0;
    } else {
        _obp_br(seq_header->color_config.color_range, br, 1);
        if (seq_header->seq_profile == 0) {
            seq_header->color_config.subsampling_x = 1;
            seq_header->color_config.subsampling_y = 1;
        } else if (seq_header->seq_profile == 1) {
            seq_header->color_config.subsampling_x = 0;
            seq_header->color_config.subsampling_y = 0;
        } else {
            if (seq_header->color_config.BitDepth == 12) {
                _obp_br(seq_header->color_config.subsampling_x, br, 1);
                if (seq_header->color_config.subsampling_x) {
                    _obp_br(seq_header->color_config.subsampling_y, br, 1);
                } else {
                    seq_header->color_config.subsampling_y = 0;
                }
            } else {
                seq_header->color_config.subsampling_x = 1;
                seq_header->color_config.subsampling_y = 0;
            }
        }
        if (seq_header->color_config.subsampling_x && seq_header->color_config.subsampling_y) {
            _obp_br(seq_header->color_config.chroma_sample_position, br, 2);
        }
    }
    _obp_br(seq_header->color_config.separate_uv_delta_q, br, 1);

color_done:
    _obp_br(seq_header->film_grain_params_present, br, 1);

    return 0;
}

int obp_parse_tile_list(uint8_t *buf, size_t buf_size, OBPTileList *tile_list, OBPError *err)
{
    size_t pos = 0;

    if (buf_size < 4) {
        snprintf(err->error, err->size, "Tile list OBU must be at least 4 bytes.");
        return -1;
    }

    tile_list->output_frame_width_in_tiles_minus_1  = buf[0];
    tile_list->output_frame_height_in_tiles_minus_1 = buf[1];
    tile_list->tile_count_minus_1                   = (((uint16_t) buf[2]) << 8) | buf[3];
    pos += 4;

    for (uint16_t i = 0; i < tile_list->tile_count_minus_1; i++) {
        if (pos + 5 > buf_size) {
            snprintf(err->error, err->size, "Tile list OBU malformed: Not enough bytes for next tile_list_entry().");
            return -1;
        }

        tile_list->tile_list_entry[i].anchor_frame_idx       = buf[pos];
        tile_list->tile_list_entry[i].anchor_tile_row        = buf[pos + 1];
        tile_list->tile_list_entry[i].anchor_tile_col        = buf[pos + 2];
        tile_list->tile_list_entry[i].tile_data_size_minus_1 = (((uint16_t) buf[pos + 3]) << 8) | buf[pos + 4];
        pos += 5;

        size_t N = 8 * (((size_t) tile_list->tile_list_entry[i].tile_data_size_minus_1) + 1);

        if (pos + N > buf_size) {
            snprintf(err->error, err->size, "Tile list OBU malformed: Not enough bytes for next tile_list_entry()'s data.");
            return -1;
        }

        tile_list->tile_list_entry[i].coded_tile_data      = buf + pos;
        tile_list->tile_list_entry[i].coded_tile_data_size = N;
        pos += N;
    }

    return 0;
}

int obp_parse_tile_group(uint8_t *buf, size_t buf_size, OBPFrameHeader *frame_header, OBPTileGroup *tile_group,
                         int *SeenFrameHeader, OBPError *err)
{
    _OBPBitReader b   = _obp_new_br(buf, buf_size);
    _OBPBitReader *br = &b;

    tile_group->NumTiles                        = frame_header->tile_info.TileCols * frame_header->tile_info.TileRows;
    size_t startBitPos                          = 0;
    tile_group->tile_start_and_end_present_flag = 0;

    if (tile_group->NumTiles > 1) {
        _obp_br(tile_group->tile_start_and_end_present_flag, br, 1);
    }
    if (tile_group->NumTiles == 1 || !tile_group->tile_start_and_end_present_flag) {
        tile_group->tg_start = 0;
        tile_group->tg_end   = tile_group->NumTiles - 1;
    } else {
        uint8_t tileBits = _obp_tile_log2(1, frame_header->tile_info.TileCols) + _obp_tile_log2(1, frame_header->tile_info.TileRows);
        _obp_br(tile_group->tg_start, br, tileBits);
        _obp_br(tile_group->tg_end, br, tileBits);
    }
    _obp_br_byte_alignment(br);
    size_t endBitPos   = _obp_br_get_pos(br);
    size_t headerBytes = (endBitPos - startBitPos) / 8;
    size_t sz          = buf_size - headerBytes;
    size_t pos         = headerBytes;

    for (uint16_t TileNum = tile_group->tg_start; TileNum <= tile_group->tg_end; TileNum++) {
        /* tileRow = TileNum / TileCols */
        /* tileCol = TileNum % TileCols */
        int lastTile     = (TileNum == tile_group->tg_end);
        if (lastTile) {
            tile_group->TileSize[TileNum] = sz;
        } else {
            uint16_t TileSizeBytes = frame_header->tile_info.tile_size_bytes_minus_1 + 1;
            uint64_t tile_size_minus_1;
            if (sz < TileSizeBytes) {
                snprintf(err->error, err->size, "Not enough bytes left to read tile size for tile %"PRIu16".", TileNum);
                return -1;
            }
            tile_size_minus_1             = _obp_le(buf + pos, TileSizeBytes);
            tile_group->TileSize[TileNum] = tile_size_minus_1 + 1;
            if (sz < tile_group->TileSize[TileNum]) {
                snprintf(err->error, err->size, "Not enough bytes to contain TileSize for tile %"PRIu16".", TileNum);
                return -1;
            }
            sz  -= tile_group->TileSize[TileNum] + TileSizeBytes;
            pos += tile_group->TileSize[TileNum] + TileSizeBytes;
        }
        /* MiRowStart = MiRowStarts[ tileRow ] */
        /* MiRowEnd = MiRowStarts[ tileRow + 1 ] */
        /* MiColStart = MiColStarts[ tileCol ] */
        /* MiColEnd = MiColStarts[ tileCol + 1 ] */
        /* CurrentQIndex = base_q_idx */
        /* init_symbol( tileSize ) */
        /* decode_tile( ) */
        /* exit_symbol( ) */
    }
    if (tile_group->tg_end == tile_group->NumTiles - 1) {
        /* if ( !disable_frame_end_update_cdf ) {
               frame_end_update_cdf( )
           }
         */
        /* decode_frame_wrapup() is handled in obp_parse_frame_header. */
        *SeenFrameHeader = 0;
    }

    return 0;
}

int obp_parse_metadata(uint8_t *buf, size_t buf_size, OBPMetadata *metadata, OBPError *err)
{
    uint64_t val;
    ptrdiff_t consumed;
    char err_buf[1024];
    _OBPBitReader b;
    _OBPBitReader *br;
    OBPError error = { &err_buf[0], 1024 };

    int ret = _obp_leb128(buf, buf_size, &val, &consumed, &error);
    if (ret < 0) {
        snprintf(err->error, err->size, "Couldn't read metadata type: %s", error.error);
        return -1;
    }
    metadata->metadata_type = val;

    b  = _obp_new_br(buf + consumed, buf_size - consumed);
    br = &b;

    if (metadata->metadata_type == OBP_METADATA_TYPE_HDR_CLL) {
        _obp_br(metadata->metadata_hdr_cll.max_cll, br, 16);
        _obp_br(metadata->metadata_hdr_cll.max_fall, br, 16);
    } else if (metadata->metadata_type == OBP_METADATA_TYPE_HDR_MDCV) {
        for (int i = 0; i < 3; i++) {
            _obp_br(metadata->metadata_hdr_mdcv.primary_chromaticity_x[i], br, 16);
            _obp_br(metadata->metadata_hdr_mdcv.primary_chromaticity_y[i], br, 16);
        }
        _obp_br(metadata->metadata_hdr_mdcv.white_point_chromaticity_x, br, 16);
        _obp_br(metadata->metadata_hdr_mdcv.white_point_chromaticity_y, br, 16);
        _obp_br(metadata->metadata_hdr_mdcv.luminance_max, br, 32);
        _obp_br(metadata->metadata_hdr_mdcv.luminance_min, br, 32);
    } else if (metadata->metadata_type == OBP_METADATA_TYPE_SCALABILITY) {
        _obp_br(metadata->metadata_scalability.scalability_mode_idc, br, 8);
        if (metadata->metadata_scalability.scalability_mode_idc) {
            /* scalability_structure() */
            _obp_br(metadata->metadata_scalability.scalability_structure.spatial_layers_cnt_minus_1, br, 2);
            _obp_br(metadata->metadata_scalability.scalability_structure.spatial_layer_dimensions_present_flag, br, 1);
            _obp_br(metadata->metadata_scalability.scalability_structure.spatial_layer_description_present_flag, br, 1);
            _obp_br(metadata->metadata_scalability.scalability_structure.temporal_group_description_present_flag, br, 1);
            _obp_br(metadata->metadata_scalability.scalability_structure.scalability_structure_reserved_3bits, br, 3);
            if (metadata->metadata_scalability.scalability_structure.spatial_layer_dimensions_present_flag) {
                for (uint8_t i = 0; i < metadata->metadata_scalability.scalability_structure.spatial_layers_cnt_minus_1; i++) {
                    _obp_br(metadata->metadata_scalability.scalability_structure.spatial_layer_max_width[i], br, 16);
                    _obp_br(metadata->metadata_scalability.scalability_structure.spatial_layer_max_height[i], br, 16);
                }
            }
            if (metadata->metadata_scalability.scalability_structure.spatial_layer_description_present_flag) {
                for (uint8_t i = 0; i < metadata->metadata_scalability.scalability_structure.spatial_layers_cnt_minus_1; i++) {
                    _obp_br(metadata->metadata_scalability.scalability_structure.spatial_layer_ref_id[i], br, 8);
                }
            }
            if (metadata->metadata_scalability.scalability_structure.temporal_group_description_present_flag) {
                _obp_br(metadata->metadata_scalability.scalability_structure.temporal_group_size, br, 8);
                for (uint8_t i = 0; i < metadata->metadata_scalability.scalability_structure.temporal_group_size; i++) {
                    _obp_br(metadata->metadata_scalability.scalability_structure.temporal_group_temporal_id[i], br, 3);
                    _obp_br(metadata->metadata_scalability.scalability_structure.temporal_group_temporal_switching_up_point_flag[i], br, 1);
                    _obp_br(metadata->metadata_scalability.scalability_structure.temporal_group_spatial_switching_up_point_flag[i], br, 1);
                    _obp_br(metadata->metadata_scalability.scalability_structure.temporal_group_ref_cnt[i], br, 3);
                    for (uint8_t j = 0; j < metadata->metadata_scalability.scalability_structure.temporal_group_ref_cnt[i]; j++) {
                        _obp_br(metadata->metadata_scalability.scalability_structure.temporal_group_ref_pic_diff[i][j], br, 8);
                    }
                }
            }
        }
    } else if (metadata->metadata_type == OBP_METADATA_TYPE_ITUT_T35) {
        size_t offset = 1;
        _obp_br(metadata->metadata_itut_t35.itu_t_t35_country_code, br, 8);
        if (metadata->metadata_itut_t35.itu_t_t35_country_code == 0xFF) {
            _obp_br(metadata->metadata_itut_t35.itu_t_t35_country_code_extension_byte, br, 8);
            offset++;
        }
        metadata->metadata_itut_t35.itu_t_t35_payload_bytes = buf + consumed + offset;
        int non_zero_bytes_seen = 0;
        /*
         * OBUs with byte payloads at the end have a dumb property where you need to
         * know the trailing bits *before* you parse the OBU, despite the way the spec
         * the syntax displayed and defined. SO as a result, you need to find the *second*
         * non-zero byte at the end of the OBU payload, rather than the last one, as
         * the note in the ITU T.35 part of the spec says.
         */
        for (size_t i = buf_size - consumed - offset - 1; i > 0; i--) {
            if (metadata->metadata_itut_t35.itu_t_t35_payload_bytes[i] != 0) {
                non_zero_bytes_seen++;
                if (non_zero_bytes_seen == 2) {
                    metadata->metadata_itut_t35.itu_t_t35_payload_bytes_size = i + 1;
                }
            }
        }
    } else if (metadata->metadata_type == OBP_METADATA_TYPE_TIMECODE) {
        _obp_br(metadata->metadata_timecode.counting_type, br, 5);
        _obp_br(metadata->metadata_timecode.full_timestamp_flag, br, 1);
        _obp_br(metadata->metadata_timecode.discontinuity_flag, br, 1);
        _obp_br(metadata->metadata_timecode.cnt_dropped_flag, br, 1);
        _obp_br(metadata->metadata_timecode.n_frames, br, 9);
        if (metadata->metadata_timecode.full_timestamp_flag) {
            _obp_br(metadata->metadata_timecode.seconds_value, br, 6);
            _obp_br(metadata->metadata_timecode.minutes_value, br, 6);
            _obp_br(metadata->metadata_timecode.hours_value, br, 5);
        } else {
            _obp_br(metadata->metadata_timecode.seconds_flag, br, 1);
            if (metadata->metadata_timecode.seconds_flag) {
                _obp_br(metadata->metadata_timecode.seconds_value, br, 6);
                _obp_br(metadata->metadata_timecode.minutes_flag, br, 1);
                if (metadata->metadata_timecode.minutes_flag) {
                    _obp_br(metadata->metadata_timecode.minutes_value, br, 6);
                    _obp_br(metadata->metadata_timecode.hours_flag, br, 1);
                    if (metadata->metadata_timecode.hours_flag) {
                        _obp_br(metadata->metadata_timecode.hours_value, br, 5);
                    }
                }
            }
        }
        _obp_br(metadata->metadata_timecode.time_offset_length, br, 5);
        if (metadata->metadata_timecode.time_offset_length > 0) {
             _obp_br(metadata->metadata_timecode.time_offset_value, br, metadata->metadata_timecode.time_offset_length);
        }
    } else if (metadata->metadata_type >= 6 && metadata->metadata_type <= 31) {
        metadata->unregistered.buf      = buf + consumed;
        metadata->unregistered.buf_size = buf_size - consumed;
    } else {
        snprintf(err->error, err->size, "Invalid metadata type: %"PRIu32"\n", metadata->metadata_type);
        return -1;
    }

    return 0;
}

int obp_parse_frame(uint8_t *buf, size_t buf_size, OBPSequenceHeader *seq, OBPState *state,
                    int temporal_id, int spatial_id, OBPFrameHeader *fh, OBPTileGroup *tile_group,
                    int *SeenFrameHeader, OBPError *err)
{
    size_t startBitPos = 0, endBitPos, headerBytes;
    int ret = obp_parse_frame_header(buf, buf_size, seq, state, temporal_id, spatial_id, fh, SeenFrameHeader, err);
    if (ret < 0) {
        return -1;
    }
    endBitPos   = state->frame_header_end_pos;
    headerBytes = (endBitPos - startBitPos) / 8;
    return obp_parse_tile_group(buf + headerBytes, buf_size - headerBytes, fh, tile_group, SeenFrameHeader, err);
}

int obp_parse_frame_header(uint8_t *buf, size_t buf_size, OBPSequenceHeader *seq, OBPState *state,
                           int temporal_id, int spatial_id, OBPFrameHeader *fh, int *SeenFrameHeader, OBPError *err)
{
    _OBPBitReader b   = _obp_new_br(buf, buf_size);
    _OBPBitReader *br = &b;

    if (*SeenFrameHeader == 1) {
        if (!state->prev_filled) {
            snprintf(err->error, err->size, "SeenFrameHeader is one, but no previous header exists in state.");
            return -1;
        }
        *fh = state->prev;
        return 0;
    }

    *SeenFrameHeader = 1;

    /* uncompressed_header() */
    int idLen = 0; /* only set to 0 to shut up a compiler warning. */
    if (seq->frame_id_numbers_present_flag) {
        idLen = seq->additional_frame_id_length_minus_1 + seq->delta_frame_id_length_minus_2 + 3;
    }
    uint8_t allFrames = 255; /* (1 << 8) - 1 */
    int FrameIsIntra;
    if (seq->reduced_still_picture_header) {
        fh->show_existing_frame = 0;
        fh->frame_type          = OBP_KEY_FRAME;
        FrameIsIntra            = 1;
        fh->show_frame          = 1;
        fh->showable_frame      = 1;
    } else {
        _obp_br(fh->show_existing_frame, br, 1);
        if (fh->show_existing_frame) {
            _obp_br(fh->frame_to_show_map_idx, br, 3);
            if (seq->decoder_model_info_present_flag && !seq->timing_info.equal_picture_interval) {
                /* temporal_point_info() */
                uint8_t n = seq->decoder_model_info.frame_presentation_time_length_minus_1 + 1;
                _obp_br(fh->temporal_point_info.frame_presentation_time, br, n);
            }
            fh->refresh_frame_flags = 0;
            if (seq->frame_id_numbers_present_flag) {
                assert(idLen <= 255);
                _obp_br(fh->display_frame_id, br, (uint8_t) idLen);
            }
            fh->frame_type = state->RefFrameType[fh->frame_to_show_map_idx];
            if (fh->frame_type == OBP_KEY_FRAME) {
                fh->refresh_frame_flags = allFrames;
            }
            if (seq->film_grain_params_present) {
                /* load_grain_params() */
                fh->film_grain_params = state->RefGrainParams[fh->frame_to_show_map_idx];
            }
            return 0;
        }
        _obp_br(fh->frame_type, br, 2);
        FrameIsIntra = (fh->frame_type == OBP_INTRA_ONLY_FRAME || fh->frame_type == OBP_KEY_FRAME);
        _obp_br(fh->show_frame, br, 1);
        if (fh->show_frame && seq->decoder_model_info_present_flag && !seq->timing_info.equal_picture_interval){
            /* temporal_point_info() */
            uint8_t n = seq->decoder_model_info.frame_presentation_time_length_minus_1 + 1;
            _obp_br(fh->temporal_point_info.frame_presentation_time, br, n);
        }
        if (fh->show_frame) {
            fh->showable_frame = (fh->frame_type != OBP_KEY_FRAME);
        } else {
            _obp_br(fh->showable_frame, br, 1);
        }
        if (fh->frame_type == OBP_SWITCH_FRAME || (fh->frame_type == OBP_KEY_FRAME && fh->show_frame)) {
            fh->error_resilient_mode = 1;
        } else {
            _obp_br(fh->error_resilient_mode, br, 1);
        }
    }
    if (fh->frame_type == OBP_KEY_FRAME && fh->show_frame) {
        for (int i = 0; i < 8; i++) {
            state->RefValid[i]     = 0;
            state->RefOrderHint[i] = 0;
        }
        for (int i = 0; i < 7; i++) {
            state->OrderHint[1 + i] = 0;
        }
    }
    _obp_br(fh->disable_cdf_update, br, 1);
    if (seq->seq_force_screen_content_tools == 2) {
        _obp_br(fh->allow_screen_content_tools, br, 1);
    } else {
        fh->allow_screen_content_tools = seq->seq_force_screen_content_tools;
    }
    if (fh->allow_screen_content_tools) {
        if (seq->seq_force_integer_mv == 2) {
            _obp_br(fh->force_integer_mv, br, 1);
        } else {
            fh->force_integer_mv = seq->seq_force_integer_mv;
        }
    } else {
        fh->force_integer_mv = 0;
    }
    if (FrameIsIntra) {
         fh->force_integer_mv = 1;
    }
    if (seq->frame_id_numbers_present_flag) {
        /*PrevFrameID = current_frame_id */
        assert(idLen <= 255);
        _obp_br(fh->current_frame_id, br, idLen);
        /* mark_ref_frames(idLen) */
        uint8_t diffLen = seq->delta_frame_id_length_minus_2 + 2;
        for (int i = 0; i < 8; i++) {
            if (fh->current_frame_id > (((uint32_t)1) << diffLen)) {
                if (state->RefFrameId[i] > fh->current_frame_id || state->RefFrameId[i] < (fh->current_frame_id - (1 << diffLen))) {
                    state->RefValid[i] = 0;
                }
            } else {
                if (state->RefFrameId[i] > fh->current_frame_id && state->RefFrameId[i] < ((1 << idLen) + fh->current_frame_id + (1 << diffLen))) {
                    state->RefValid[i] = 0;
                }
            }
        }
    } else {
        fh->current_frame_id = 0;
    }
    if (fh->frame_type == OBP_SWITCH_FRAME) {
        fh->frame_size_override_flag = 1;
    } else if (seq->reduced_still_picture_header) {
        fh->frame_size_override_flag = 0;
    } else {
        _obp_br(fh->frame_size_override_flag, br, 1);
    }
    if (seq->OrderHintBits) { /* Added by me. */
        _obp_br(fh->order_hint, br, seq->OrderHintBits);
    } else {
        fh->order_hint = 0;
    }
    uint8_t OrderHint = fh->order_hint;
    if (FrameIsIntra || fh->error_resilient_mode) {
        fh->primary_ref_frame = 7;
    } else {
        _obp_br(fh->primary_ref_frame, br, 3);
    }
    if (seq->decoder_model_info_present_flag) {
        _obp_br(fh->buffer_removal_time_present_flag, br, 1);
        if (fh->buffer_removal_time_present_flag) {
            for (uint8_t opNum = 0; opNum <= seq->operating_points_cnt_minus_1; opNum++) {
                if (seq->decoder_model_present_for_this_op[opNum]) {
                    uint8_t opPtIdc = seq->operating_point_idc[opNum];
                    int inTemporalLayer = (opPtIdc >> temporal_id) & 1;
                    int inSpatialLayer = (opPtIdc >> (spatial_id + 8)) & 1;
                    if (opPtIdc == 0 || (inTemporalLayer && inSpatialLayer)) {
                        uint8_t n = seq->decoder_model_info.buffer_removal_time_length_minus_1 + 1;
                        _obp_br(fh->buffer_removal_time[opNum], br, n);
                    }
                }
            }
        }
    }
    fh->allow_high_precision_mv = 0;
    fh->use_ref_frame_mvs = 0;
    fh->allow_intrabc = 0;
    if (fh->frame_type == OBP_SWITCH_FRAME || (fh->frame_type == OBP_KEY_FRAME && fh->show_frame)) {
        fh->refresh_frame_flags = allFrames;
    } else {
        _obp_br(fh->refresh_frame_flags, br, 8);
    }
    if (!FrameIsIntra || fh->refresh_frame_flags != allFrames) {
        if (fh->error_resilient_mode && seq->enable_order_hint) {
            for (int i = 0; i < 8; i++) {
                _obp_br(fh->ref_order_hint[i], br, seq->OrderHintBits);
                if (fh->ref_order_hint[i] != state->RefOrderHint[i]) {
                    state->RefValid[i] = 0;
                }
            }
        }
    }
    uint32_t FrameWidth = 0, FrameHeight = 0;
    uint32_t UpscaledWidth;
    uint32_t MiCols, MiRows;
    if (FrameIsIntra) {
        /* frame_size() */
        if (fh->frame_size_override_flag) {
            uint8_t n = seq->frame_width_bits_minus_1 + 1;
            _obp_br(fh->frame_width_minus_1, br, n);
            n = seq->frame_height_bits_minus_1 + 1;
            _obp_br(fh->frame_height_minus_1, br, n);
            FrameWidth  = fh->frame_width_minus_1 + 1;
            FrameHeight = fh->frame_height_minus_1 + 1;
        } else {
            FrameWidth  = seq->max_frame_width_minus_1 + 1;
            FrameHeight = seq->max_frame_height_minus_1 + 1;
        }
        /* superres_params() */
        uint32_t SuperresDenom;
        if (seq->enable_superres) {
            _obp_br(fh->superres_params.use_superres, br, 1);
        } else {
            fh->superres_params.use_superres = 0;
        }
        if (fh->superres_params.use_superres) {
            _obp_br(fh->superres_params.coded_denom, br, 3);
            SuperresDenom = fh->superres_params.coded_denom + 9;
        } else {
            SuperresDenom = 8;
        }
        UpscaledWidth = FrameWidth;
        FrameWidth = (UpscaledWidth * 8 + (SuperresDenom / 2)) / SuperresDenom;
        /* compute_image_size() */
        MiCols = 2 * ((FrameWidth + 7) >> 3);
        MiRows = 2 * ((FrameHeight + 7) >> 3);
        /* render_size() */
        _obp_br(fh->render_and_frame_size_different, br, 1);
        if (fh->render_and_frame_size_different == 1) {
            _obp_br(fh->render_width_minus_1, br, 16);
            _obp_br(fh->render_height_minus_1, br, 16);
            fh->RenderWidth  = fh->render_width_minus_1 + 1;
            fh->RenderHeight = fh->render_height_minus_1 + 1;
        } else {
            fh->RenderWidth  = UpscaledWidth;
            fh->RenderHeight = FrameHeight;
        }
        if (fh->allow_screen_content_tools && UpscaledWidth == FrameWidth) {
            _obp_br(fh->allow_intrabc, br, 1);
        }
    } else {
        if (!seq->enable_order_hint) {
            fh->frame_refs_short_signaling = 0;
        } else {
            _obp_br(fh->frame_refs_short_signaling, br, 1);
            if (fh->frame_refs_short_signaling) {
                int ret;
                char err_buf[1024];
                OBPError error = { &err_buf[0], 1024 };
                _obp_br(fh->last_frame_idx, br, 3);
                _obp_br(fh->gold_frame_idx, br, 3);
                ret = _obp_set_frame_refs(fh, seq, state, &error);
                if (ret < 0) {
                    snprintf(err->error, err->size, "Failed to set frame refs: %s", error.error);
                    return -1;
                }
            }
        }
        for (int i = 0; i < 7; i++) {
            if (!fh->frame_refs_short_signaling) {
                _obp_br(fh->ref_frame_idx[i], br, 3);
            }
            if (seq->frame_id_numbers_present_flag) {
                uint8_t n = seq->delta_frame_id_length_minus_2 + 2;
                _obp_br(fh->delta_frame_id_minus_1[i], br, n);
                uint8_t DeltaFrameId    = fh->delta_frame_id_minus_1[i] + 1;
                uint8_t expectedFrameId = ((fh->current_frame_id + (1 << idLen) - DeltaFrameId) % (1 << idLen));
                if (state->RefFrameId[fh->ref_frame_idx[i]] != expectedFrameId) {
                    snprintf(err->error, err->size, "state->RefFrameId[fh->ref_frame_idx[i]] != expectedFrameId (%"PRIu8" vs %"PRIu8")",
                             state->RefFrameId[fh->ref_frame_idx[i]], expectedFrameId);
                    return -1;
                }
            }
        }
        if (fh->frame_size_override_flag && !fh->error_resilient_mode) {
            for (int i = 0; i < 7; i++) {
                _obp_br(fh->found_ref, br, 1);
                if (fh->found_ref == 1) {
                    UpscaledWidth    = state->RefUpscaledWidth[fh->ref_frame_idx[i]];
                    FrameWidth       = UpscaledWidth;
                    FrameHeight      = state->RefFrameHeight[fh->ref_frame_idx[i]];
                    fh->RenderWidth  = state->RefRenderWidth[fh->ref_frame_idx[i]];
                    fh->RenderHeight = state->RefRenderHeight[fh->ref_frame_idx[i]];
                    break;
                }
            }
            if (fh->found_ref == 0) {
                /* frame_size() */
                if (fh->frame_size_override_flag) {
                    uint8_t n = seq->frame_width_bits_minus_1 + 1;
                    _obp_br(fh->frame_width_minus_1, br, n);
                    n = seq->frame_height_bits_minus_1 + 1;
                    _obp_br(fh->frame_height_minus_1, br, n);
                    FrameWidth  = fh->frame_width_minus_1 + 1;
                    FrameHeight = fh->frame_height_minus_1 + 1;
                } else {
                    FrameWidth  = seq->max_frame_width_minus_1 + 1;
                    FrameHeight = seq->max_frame_height_minus_1 + 1;
                }
                /* superres_params() */
                uint32_t SuperresDenom;
                if (seq->enable_superres) {
                    _obp_br(fh->superres_params.use_superres, br, 1);
                } else {
                    fh->superres_params.use_superres = 0;
                }
                if (fh->superres_params.use_superres) {
                    _obp_br(fh->superres_params.coded_denom, br, 3);
                    SuperresDenom = fh->superres_params.coded_denom + 9;
                } else {
                    SuperresDenom = 8;
                }
                UpscaledWidth = FrameWidth;
                FrameWidth = (UpscaledWidth * 8 + (SuperresDenom / 2)) / SuperresDenom;
                /* compute_image_size() */
                MiCols = 2 * ((FrameWidth + 7) >> 3);
                MiRows = 2 * ((FrameHeight + 7) >> 3);
                /* render_size() */
                _obp_br(fh->render_and_frame_size_different, br, 1);
                if (fh->render_and_frame_size_different == 1) {
                    _obp_br(fh->render_width_minus_1, br, 16);
                    _obp_br(fh->render_height_minus_1, br, 16);
                    fh->RenderWidth  = fh->render_width_minus_1 + 1;
                    fh->RenderHeight = fh->render_height_minus_1 + 1;
                } else {
                    fh->RenderWidth  = UpscaledWidth;
                    fh->RenderHeight = FrameHeight;
                }
            } else {
                /* superres_params() */
                uint32_t SuperresDenom;
                if (seq->enable_superres) {
                    _obp_br(fh->superres_params.use_superres, br, 1);
                } else {
                    fh->superres_params.use_superres = 0;
                }
                if (fh->superres_params.use_superres) {
                    _obp_br(fh->superres_params.coded_denom, br, 3);
                    SuperresDenom = fh->superres_params.coded_denom + 9;
                } else {
                    SuperresDenom = 8;
                }
                UpscaledWidth = FrameWidth;
                FrameWidth = (UpscaledWidth * 8 + (SuperresDenom / 2)) / SuperresDenom;
                /* compute_image_size() */
                MiCols = 2 * ((FrameWidth + 7) >> 3);
                MiRows = 2 * ((FrameHeight + 7) >> 3);
            }
        } else {
            /* frame_size() */
            if (fh->frame_size_override_flag) {
                uint8_t n = seq->frame_width_bits_minus_1 + 1;
                _obp_br(fh->frame_width_minus_1, br, n);
                n = seq->frame_height_bits_minus_1 + 1;
                _obp_br(fh->frame_height_minus_1, br, n);
                FrameWidth  = fh->frame_width_minus_1 + 1;
                FrameHeight = fh->frame_height_minus_1 + 1;
            } else {
                FrameWidth  = seq->max_frame_width_minus_1 + 1;
                FrameHeight = seq->max_frame_height_minus_1 + 1;
            }
            /* superres_params() */
            uint32_t SuperresDenom;
            if (seq->enable_superres) {
                _obp_br(fh->superres_params.use_superres, br, 1);
            } else {
                fh->superres_params.use_superres = 0;
            }
            if (fh->superres_params.use_superres) {
                _obp_br(fh->superres_params.coded_denom, br, 3);
                SuperresDenom = fh->superres_params.coded_denom + 9;
            } else {
                SuperresDenom = 8;
            }
            UpscaledWidth = FrameWidth;
            FrameWidth = (UpscaledWidth * 8 + (SuperresDenom / 2)) / SuperresDenom;
            /* compute_image_size() */
            MiCols = 2 * ((FrameWidth + 7) >> 3);
            MiRows = 2 * ((FrameHeight + 7) >> 3);
            /* render_size() */
            _obp_br(fh->render_and_frame_size_different, br, 1);
            if (fh->render_and_frame_size_different == 1) {
                _obp_br(fh->render_width_minus_1, br, 16);
                _obp_br(fh->render_height_minus_1, br, 16);
                fh->RenderWidth  = fh->render_width_minus_1 + 1;
                fh->RenderHeight = fh->render_height_minus_1 + 1;
            } else {
                fh->RenderWidth  = UpscaledWidth;
                fh->RenderHeight = FrameHeight;
            }
        }
        if (fh->force_integer_mv) {
            fh->allow_high_precision_mv = 0;
        } else {
            _obp_br(fh->allow_high_precision_mv, br, 1);
        }
        /* read_interpolation_filer() */
        _obp_br(fh->interpolation_filter.is_filter_switchable, br, 1);
        if (fh->interpolation_filter.is_filter_switchable) {
            fh->interpolation_filter.interpolation_filter = 4;
        } else {
            _obp_br(fh->interpolation_filter.interpolation_filter, br, 2);
        }
        _obp_br(fh->is_motion_mode_switchable, br, 1);
        if (fh->error_resilient_mode || !seq->enable_ref_frame_mvs) {
            fh->use_ref_frame_mvs = 0;
        } else {
            _obp_br(fh->use_ref_frame_mvs, br, 1);
        }
        for (int i = 0; i < 7; i++) {
            int refFrame = 1 + i;
            uint8_t hint = state->RefOrderHint[fh->ref_frame_idx[i]];
            state->OrderHint[refFrame] = hint;
            if (!seq->enable_order_hint) {
                state->RefFrameSignBias[refFrame] = 0;
            } else {
                state->RefFrameSignBias[refFrame] = _obp_get_relative_dist((int32_t) hint, (int32_t) OrderHint, seq);
            }
        }
    }
    if (seq->reduced_still_picture_header || fh->disable_cdf_update) {
        fh->disable_frame_end_update_cdf = 1;
    } else {
        _obp_br(fh->disable_frame_end_update_cdf, br, 1);
    }
    int FeatureEnabled[8][8];
    int16_t FeatureData[8][8];
    if (fh->primary_ref_frame == 7) {
        /* init_non_coeff_cdfs() not relevant to OBU parsing. */
        /* setup_past_independence() */
        for (int i = 1; i < 7; i++) {
            fh->global_motion_params.gm_type[i] = 0;
            for (int j = 0; j < 6; j++) {
                fh->global_motion_params.gm_params[i][j] = (i % 3 == 2) ? (((uint32_t)1) << 16) : 0;
            }
        }
        fh->loop_filter_params.loop_filter_delta_enabled = 1;
        fh->loop_filter_params.loop_filter_ref_deltas[0] = 1;
        fh->loop_filter_params.loop_filter_ref_deltas[1] = 0;
        fh->loop_filter_params.loop_filter_ref_deltas[2] = 0;
        fh->loop_filter_params.loop_filter_ref_deltas[3] = 0;
        fh->loop_filter_params.loop_filter_ref_deltas[4] = 0;
        fh->loop_filter_params.loop_filter_ref_deltas[5] = -1;
        fh->loop_filter_params.loop_filter_ref_deltas[6] = -1;
        fh->loop_filter_params.loop_filter_ref_deltas[7] = -1;
        for (int i = 0; i < 2; i++) {
            fh->loop_filter_params.loop_filter_mode_deltas[i] = 0;
        }
    } else {
        /* load_cdfs() not relevant to OBU parsing. */
        /* load_previous */
        int prevFrame = fh->ref_frame_idx[fh->primary_ref_frame];
        for (int i = 0; i > 8; i++) {
            for (int j = 0; j < 6; j++) {
                fh->global_motion_params.prev_gm_params[i][j] = state->SavedGmParams[prevFrame][i][j];
            }
        }
        /* load_loop_filter_params() */
        for (int i = 0; i < 8; i++) {
            fh->loop_filter_params.loop_filter_ref_deltas[i]  = state->SavedLoopFilterRefDeltas[prevFrame][i];
            fh->loop_filter_params.loop_filter_mode_deltas[i] = state->SavedLoopFilterModeDeltas[prevFrame][i];
        }
        /* load_segmentation_params() */
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                FeatureEnabled[i][j] = state->SavedFeatureEnabled[prevFrame][i][j];
                FeatureData[i][j]    = state->SavedFeatureData[prevFrame][i][j];
            }
        }
    }
    /* Not relevant to OBU parsing:
           if (fh->use_ref_frame_mvs) {
               motion_field_estimation()
           }
     */
    /* tile_info() */
    uint32_t sbCols          = seq->use_128x128_superblock ? ((MiCols + 31) >> 5) : ((MiCols + 15) >> 4);
    uint32_t sbRows          = seq->use_128x128_superblock ? ((MiRows + 31) >> 5) : ((MiRows + 15) >> 4);
    uint32_t sbShift         = seq->use_128x128_superblock ? 5 : 4;
    uint32_t sbSize          = sbShift + 2;
    uint32_t maxTileWidthSb  = 4096 >> sbSize;
    uint32_t maxTileAreaSb   = (4096 * 2304) >> (2 * sbSize);
    uint32_t minLog2TileCols = _obp_tile_log2(maxTileWidthSb, sbCols);
    uint32_t maxLog2TileCols = _obp_tile_log2(1, _OBP_MIN(sbCols, 64));
    uint32_t maxLog2TileRows = _obp_tile_log2(1, _OBP_MIN(sbRows, 64));
    uint32_t minLog2Tiles    = _OBP_MAX(minLog2TileCols, _obp_tile_log2(maxTileAreaSb, sbRows * sbCols));
    uint32_t minLog2TileRows, TileColsLog2, TileRowsLog2;
    _obp_br(fh->tile_info.uniform_tile_spacing_flag, br, 1);
    if (fh->tile_info.uniform_tile_spacing_flag) {
        TileColsLog2 = minLog2TileCols;
        while (TileColsLog2 < maxLog2TileCols) {
            int increment_tile_cols_log2;
            _obp_br(increment_tile_cols_log2, br, 1);
            if (increment_tile_cols_log2 == 1) {
                TileColsLog2++;
            } else {
                break;
            }
        }
        uint32_t tileWidthSb = (sbCols + (1 << TileColsLog2) - 1) >> TileColsLog2;
        int i = 0;
        for (uint32_t startSb = 0; startSb < sbCols; startSb += tileWidthSb) {
            /* MiColStarts[i] = startSb << sbShift; */
            i += 1;
        }
        /*MiColStarts[i]           = MiCols; */
        fh->tile_info.TileCols   = i;

        minLog2TileRows = _OBP_MAX((int64_t)minLog2Tiles - (int64_t)TileColsLog2, 0);
        TileRowsLog2 = minLog2TileRows;
        while (TileRowsLog2 < maxLog2TileRows) {
            int increment_tile_rows_log2;
            _obp_br(increment_tile_rows_log2, br, 1);
            if (increment_tile_rows_log2 == 1) {
                TileRowsLog2++;
            } else {
                break;
            }
        }
        uint32_t tileHeightSb = (sbRows + (1 << TileRowsLog2) - 1) >> TileRowsLog2;
        i = 0;
        for (uint32_t startSb = 0; startSb < sbRows; startSb += tileHeightSb) {
            /*MiRowStarts[i] = startSb << sbShift;*/
            i += 1;
        }
        /*MiRowStarts[i]           = MiRows;*/
        fh->tile_info.TileRows   = i;
    } else {
        uint32_t widestTileSb = 0;
        uint32_t startSb      = 0;
        uint32_t i, maxTileHeightSb;
        for (i = 0; startSb < sbCols; i++) {
            int ret;
            char err_buf[1024];
            OBPError error = { &err_buf[0], 1024 };
            uint32_t maxWidth, sizeSb;
            uint32_t width_in_sbs_minus_1;
            /* MiColStarts[i] = startSb << sbShift; */
            maxWidth       = _OBP_MIN(sbCols - startSb, maxTileWidthSb);
            ret            = _obp_ns(br, maxWidth, &width_in_sbs_minus_1, &error);
            if (ret < 0) {
                snprintf(err->error, err->size, "Couldn't read width_in_sbs_minus_1: %s", error.error);
                return -1;
            }
            sizeSb        = width_in_sbs_minus_1 + 1;
            widestTileSb  = _OBP_MAX(sizeSb, widestTileSb);
            startSb      += sizeSb;
        }
        /*MiColStarts[i]         = MiCols;*/
        fh->tile_info.TileCols = i;
        TileColsLog2           = _obp_tile_log2(1, fh->tile_info.TileCols);

        if (minLog2Tiles > 0) {
            maxTileAreaSb = (sbRows * sbCols) >> (minLog2Tiles + 1);
        } else {
            maxTileAreaSb = sbRows * sbCols;
        }
        maxTileHeightSb = _OBP_MAX(maxTileAreaSb / widestTileSb, 1);

        startSb = 0;
        for (i = 0; startSb < sbRows; i++) {
            int ret;
            char err_buf[1024];
            OBPError error = { &err_buf[0], 1024 };
            uint32_t maxHeight, sizeSb;
            uint32_t height_in_sbs_minus_1;
            /*MiRowStarts[i] = startSb << sbShift;*/
            maxHeight      = _OBP_MIN(sbRows - startSb, maxTileHeightSb);
            ret            = _obp_ns(br, maxHeight, &height_in_sbs_minus_1, &error);
            if (ret < 0) {
                snprintf(err->error, err->size, "Couldn't read height_in_sbs_minus_1: %s", error.error);
                return -1;
            }
            sizeSb   = height_in_sbs_minus_1 + 1;
            startSb += sizeSb;
        }
        /*MiRowStarts[i]          = MiRows*/;
        fh->tile_info.TileRows = i;
        TileRowsLog2           = _obp_tile_log2(1, fh->tile_info.TileRows);
    }
    if (TileColsLog2 > 0 || TileRowsLog2 > 0) {
        _obp_br(fh->tile_info.context_update_tile_id, br, (TileColsLog2 + TileRowsLog2));
        _obp_br(fh->tile_info.tile_size_bytes_minus_1, br, 2);
        /*TileSizeBytes = fh->tile_info.tile_size_bytes_minus_1 + 1;*/
    } else {
        fh->tile_info.context_update_tile_id = 0;
    }
    /* quantization_params() */
    _obp_br(fh->quantization_params.base_q_idx, br, 8);
    int32_t DeltaQYDc, DeltaQUDc, DeltaQUAc, DeltaQVDc, DeltaQVAc;
    int ret = _obp_read_delta_q(br, &DeltaQYDc, err);
    if (ret < 0) {
        return -1;
    }
    if (seq->color_config.NumPlanes > 1) {
        int ret;
        if (seq->color_config.separate_uv_delta_q) {
            _obp_br(fh->quantization_params.diff_uv_delta, br, 1);
        } else {
            fh->quantization_params.diff_uv_delta = 0;
        }
        ret = _obp_read_delta_q(br, &DeltaQUDc, err);
        if (ret < 0) {
            return -1;
        }
        ret = _obp_read_delta_q(br, &DeltaQUAc, err);
        if (ret < 0) {
            return -1;
        }
        if (fh->quantization_params.diff_uv_delta) {
            ret = _obp_read_delta_q(br, &DeltaQVDc, err);
            if (ret < 0) {
                return -1;
            }
            ret = _obp_read_delta_q(br, &DeltaQVAc, err);
            if (ret < 0) {
                return -1;
            }
        } else {
            DeltaQVDc = DeltaQUDc;
            DeltaQVAc = DeltaQUAc;
        }
    } else {
        DeltaQUDc = 0;
        DeltaQUAc = 0;
        DeltaQVDc = 0;
        DeltaQVAc = 0;
    }
    _obp_br(fh->quantization_params.using_qmatrix, br, 1);
    if (fh->quantization_params.using_qmatrix) {
        _obp_br(fh->quantization_params.qm_y, br, 4);
        _obp_br(fh->quantization_params.qm_u, br, 4);
        if (!seq->color_config.separate_uv_delta_q) {
            fh->quantization_params.qm_v = fh->quantization_params.qm_u;
        } else {
            _obp_br(fh->quantization_params.qm_v, br, 4);
        }
    }
    /* segmentation_params() */
    const uint8_t Segmentation_Feature_Bits[8] = { 8, 6, 6, 6, 6, 3, 0, 0 };
    const uint8_t Segmentation_Feature_Max[8]  = { 255, 63, 63, 63, 63, 7, 0, 0 };
    const int Segmentation_Feature_Signed[8]   = { 1, 1, 1, 1, 1, 0, 0, 0 };
    _obp_br(fh->segmentation_params.segmentation_enabled, br, 1);
    if (fh->segmentation_params.segmentation_enabled == 1) {
        if (fh->primary_ref_frame == 7) {
            fh->segmentation_params.segmentation_update_map      = 1;
            fh->segmentation_params.segmentation_temporal_update = 0;
            fh->segmentation_params.segmentation_update_data     = 1;
        } else {
            _obp_br(fh->segmentation_params.segmentation_update_map, br, 1);
            if (fh->segmentation_params.segmentation_update_map) {
                _obp_br(fh->segmentation_params.segmentation_temporal_update, br, 1);
            }
            _obp_br(fh->segmentation_params.segmentation_update_data, br, 1);
        }
        if (fh->segmentation_params.segmentation_update_data == 1) {
            for (int i = 0; i < 8; i++) {
                for (int j = 0; j < 8; j++) {
                    int16_t clippedValue;
                    int16_t feature_value = 0;
                    int feature_enabled;
                    _obp_br(feature_enabled, br, 1);
                    FeatureEnabled[i][j] = feature_enabled;
                    clippedValue         = 0;
                    if (feature_enabled) {
                        uint8_t bitsToRead = Segmentation_Feature_Bits[j];
                        int16_t limit      = Segmentation_Feature_Max[j];
                        if (Segmentation_Feature_Signed[j] == 1) {
                            int32_t val;
                            ret = _obp_su(br, 1 + bitsToRead, &val, err);
                            if (ret < 0) {
                                return -1;
                            }
                            feature_value = val;
                            clippedValue  = _OBP_MAX(-limit, _OBP_MIN(limit, feature_value));
                        } else {
                            _obp_br(feature_value, br, bitsToRead);
                            clippedValue = _OBP_MAX(0, _OBP_MIN(limit, feature_value));
                        }
                    }
                    FeatureData[i][j] = clippedValue;
                }
            }
        }
    } else {
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j > 8; j++) {
                FeatureEnabled[i][j] = 0;
                FeatureData[i][j]    = 0;
            }
        }
    }
    /*int SegIdPreSkip    = 0;
    int LastActiveSegId = 0;
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            if (FeatureEnabled[i][j]) {
                LastActiveSegId = i;
                if (j >= 5) {
                    SegIdPreSkip = 1;
                }
            }
        }
    }*/
    /* delta_q_params() */
    fh->delta_q_params.delta_q_res     = 0;
    fh->delta_q_params.delta_q_present = 0;
    if (fh->quantization_params.base_q_idx > 0) {
        _obp_br(fh->delta_q_params.delta_q_present, br, 1);
    }
    if (fh->delta_q_params.delta_q_present) {
        _obp_br(fh->delta_q_params.delta_q_res, br, 2);
    }
    /* delta_lf_params() */
    fh->delta_lf_params.delta_lf_present = 0;
    fh->delta_lf_params.delta_lf_res     = 0;
    fh->delta_lf_params.delta_lf_multi   = 0;
    if (fh->delta_q_params.delta_q_present) {
        if (!fh->allow_intrabc) {
            _obp_br(fh->delta_lf_params.delta_lf_present, br, 1);
        }
        if (fh->delta_lf_params.delta_lf_present) {
            _obp_br(fh->delta_lf_params.delta_lf_res, br, 2);
            _obp_br(fh->delta_lf_params.delta_lf_multi, br, 1);
        }
    }
    /* skipped because not relevant:

       if (fh->primary_ref_frame == 7) {
           init_coeff_cdfs();
       } else {
           lnit_coeff_cdfs();
       }
     */
    int CodedLossless = 1;
    int LosslessArray[8];
    for (int segmentId = 0; segmentId < 8; segmentId++ ) {
        uint8_t qindex           = _obp_get_qindex(1, segmentId, 0, fh, FeatureEnabled, FeatureData);
        LosslessArray[segmentId] = (qindex == 0 && DeltaQYDc == 0 && DeltaQUAc == 0 && DeltaQUDc == 0 && DeltaQVAc == 0 && DeltaQVDc == 0);
        if (!LosslessArray[segmentId]) {
            CodedLossless = 0;
        }
        /* SegQMLevel not relevant to OBU parsing.*/
    }
    int AllLossless = (CodedLossless && (FrameWidth == UpscaledWidth));
    /* loop_filter_params() */
    if (CodedLossless || fh->allow_intrabc) {
        fh->loop_filter_params.loop_filter_delta_enabled = 1;
        fh->loop_filter_params.loop_filter_ref_deltas[0] = 1;
        fh->loop_filter_params.loop_filter_ref_deltas[1] = 0;
        fh->loop_filter_params.loop_filter_ref_deltas[2] = 0;
        fh->loop_filter_params.loop_filter_ref_deltas[3] = 0;
        fh->loop_filter_params.loop_filter_ref_deltas[4] = 0;
        fh->loop_filter_params.loop_filter_ref_deltas[5] = -1;
        fh->loop_filter_params.loop_filter_ref_deltas[6] = -1;
        fh->loop_filter_params.loop_filter_ref_deltas[7] = -1;
        for (int i = 0; i < 2; i++) {
            fh->loop_filter_params.loop_filter_mode_deltas[i] = 0;
        }
        /* return */
    } else {
        _obp_br(fh->loop_filter_params.loop_filter_level[0], br, 6);
        _obp_br(fh->loop_filter_params.loop_filter_level[1], br, 6);
        if (seq->color_config.NumPlanes > 1) {
            if (fh->loop_filter_params.loop_filter_level[0] || fh->loop_filter_params.loop_filter_level[1]) {
                _obp_br(fh->loop_filter_params.loop_filter_level[2], br, 6);
                _obp_br(fh->loop_filter_params.loop_filter_level[3], br, 6);
            }
        }
        _obp_br(fh->loop_filter_params.loop_filter_sharpness, br, 3);
        _obp_br(fh->loop_filter_params.loop_filter_delta_enabled, br, 1);
        if (fh->loop_filter_params.loop_filter_delta_enabled == 1) {
            _obp_br(fh->loop_filter_params.loop_filter_delta_update, br, 1);
            if (fh->loop_filter_params.loop_filter_delta_update == 1) {
                for (int i = 0; i < 8; i++) {
                    int update_ref_delta;
                    _obp_br(update_ref_delta, br, 1);
                    if (update_ref_delta) {
                        int32_t val;
                        ret = _obp_su(br, 7, &val, err);
                        if (ret < 0) {
                            return -1;
                        }
                        fh->loop_filter_params.loop_filter_ref_deltas[i] = val;
                    }
                }
                for (int i = 0; i < 2; i++) {
                    int update_mode_delta;
                    _obp_br(update_mode_delta, br, 1);
                    if (update_mode_delta) {
                        int32_t val;
                        ret = _obp_su(br, 7, &val, err);
                        if (ret < 0) {
                            return -1;
                        }
                        fh->loop_filter_params.loop_filter_mode_deltas[i] = val;
                    }
                }
            }
        }
    }
    /* cdef_params() */
    if (CodedLossless || fh->allow_intrabc || !seq->enable_cdef) {
        fh->cdef_params.cdef_bits               = 0;
        fh->cdef_params.cdef_y_pri_strength[0]  = 0;
        fh->cdef_params.cdef_y_sec_strength[0]  = 0;
        fh->cdef_params.cdef_uv_pri_strength[0] = 0;
        fh->cdef_params.cdef_uv_sec_strength[0] = 0;
        /* CdefDamping not relevant to OBU parsing. */
        /* return */
    } else {
        _obp_br(fh->cdef_params.cdef_damping_minus_3, br, 2);
        /* CdefDamping not relevant to OBU parsing. */
        _obp_br(fh->cdef_params.cdef_bits, br, 2);
        for (int i = 0; i < (1 << fh->cdef_params.cdef_bits); i++) {
            _obp_br(fh->cdef_params.cdef_y_pri_strength[i], br, 4);
            _obp_br(fh->cdef_params.cdef_y_sec_strength[i], br, 2);
            if (fh->cdef_params.cdef_y_sec_strength[i] == 3) {
                fh->cdef_params.cdef_y_sec_strength[i] += 1;
            }
            if (seq->color_config.NumPlanes > 1) {
                _obp_br(fh->cdef_params.cdef_uv_pri_strength[i], br, 4);
                _obp_br(fh->cdef_params.cdef_uv_sec_strength[i], br, 2);
                if (fh->cdef_params.cdef_uv_sec_strength[i] == 3) {
                    fh->cdef_params.cdef_uv_sec_strength[i] += 1;
                }
            }
        }
    }
    if (AllLossless || fh->allow_intrabc || !seq->enable_restoration) {
        fh->lr_params.lr_type[0] = 0;
        fh->lr_params.lr_type[1] = 0;
        fh->lr_params.lr_type[2] = 0;
    } else {
        int UsesLr       = 0;
        int usesChromaLr = 0;
        for (int i = 0; i < seq->color_config.NumPlanes; i++) {
            _obp_br(fh->lr_params.lr_type[i], br, 2);
            if (fh->lr_params.lr_type[i] != 0) {
                UsesLr = 1;
                if (i > 0) {
                    usesChromaLr = 1;
                }
            }
        }
        if (UsesLr) {
            if (seq->use_128x128_superblock) {
                _obp_br(fh->lr_params.lr_unit_shift, br, 1);
                fh->lr_params.lr_unit_shift++;
            } else {
                _obp_br(fh->lr_params.lr_unit_shift, br, 1);
                if (fh->lr_params.lr_unit_shift) {
                    uint8_t lr_unit_extra_shift;
                    _obp_br(lr_unit_extra_shift, br, 1);
                    fh->lr_params.lr_unit_shift += lr_unit_extra_shift;
                }
            }
            /* LoopRestorationSize not relevant to OBU parsing. */
            if (seq->color_config.subsampling_x && seq->color_config.subsampling_y && usesChromaLr) {
                _obp_br(fh->lr_params.lr_uv_shift, br, 1);
            } else {
                fh->lr_params.lr_uv_shift = 0;
            }
            /* LoopRestorationSize not relevant to OBU parsing. */
        }
    }
    /* read_tx_mode */
    if (CodedLossless == 1) {
        /* TxMode not relevant to OBU parsing. */
    } else {
        _obp_br(fh->tx_mode_select, br, 1);
        if (fh->tx_mode_select) {
            /* TxMode not relevant to OBU parsing. */
        } else {
            /* TxMode not relevant to OBU parsing. */
        }
    }
    /* frame_reference_mode() */
    if (FrameIsIntra) {
        fh->reference_select = 0;
    } else {
        _obp_br(fh->reference_select, br, 1);
    }
    /* skip_mode_params() */
    int skipModeAllowed;
    if (FrameIsIntra || !fh->reference_select || !seq->enable_order_hint) {
        skipModeAllowed = 0;
    } else {
        int forwardIdx       = -1;
        int backwardIdx      = -1;
        int32_t forwardHint  = 0; /* Never declare by spec! Bug? */
        int32_t backwardHint = 0; /* Never declare by spec! Bug? */
        for (int i = 0; i < 7; i++) {
            int32_t refHint = state->RefOrderHint[fh->ref_frame_idx[i]];
            if(_obp_get_relative_dist(refHint, OrderHint, seq) < 0) {
                if (forwardIdx < 0 || _obp_get_relative_dist(refHint, forwardHint, seq) > 0) {
                    forwardIdx  = i;
                    forwardHint = refHint;
                }
            } else if (_obp_get_relative_dist(refHint, OrderHint, seq) > 0) {
                if (backwardIdx < 0 || _obp_get_relative_dist(refHint, backwardHint, seq) < 0) {
                    backwardIdx  = i;
                    backwardHint = refHint;
                }
            }
        }
        if (forwardIdx < 0) {
            skipModeAllowed = 0;
        } else if (backwardIdx >= 0) {
            skipModeAllowed = 1;
            /* SkipModeFrame not relevant to OBU parsing. */
        } else {
            int     secondForwardIdx = -1;
            int32_t secondForwardHint = 0; /* Never declare by spec! Bug? */
            for (int i = 0; i < 7; i++) {
                int32_t refHint = state->RefOrderHint[fh->ref_frame_idx[i]];
                if (_obp_get_relative_dist(refHint, forwardHint, seq) < 0) {
                    if (secondForwardIdx < 0 || _obp_get_relative_dist(refHint, secondForwardHint, seq) > 0) {
                        secondForwardIdx  = i;
                        secondForwardHint = refHint;
                    }
                }
            }
            if (secondForwardIdx < 0) {
                skipModeAllowed = 0;
            } else {
                skipModeAllowed = 1;
                /* SkipModeFrame not relevant to OBU parsing. */
            }
        }
    }
    if (skipModeAllowed) {
        _obp_br(fh->skip_mode_present, br, 1);
    } else {
        fh->skip_mode_present = 0;
    }
    if (FrameIsIntra || fh->error_resilient_mode || !seq->enable_warped_motion) {
        fh->allow_warped_motion = 0;
    } else {
        _obp_br(fh->allow_warped_motion, br, 1);
    }
    _obp_br(fh->reduced_tx_set, br, 1);
    /* global_motion_params() */
    for (int ref = 1; ref < 7; ref++) {
        fh->global_motion_params.gm_type[ref] = 0;
        for(int i = 0; i < 6; i++) {
            fh->global_motion_params.gm_params[ref][i] = (i % 3 == 2) ? (((uint32_t)1) << 16) : 0;
        }
    }
    if (FrameIsIntra) {
        /* return */
    } else {
        for (int ref = 1; ref <= 7; ref++) {
            uint8_t type;
            int is_global;
            _obp_br(is_global, br, 1);
            if (is_global) {
                int is_rot_zoom;
                _obp_br(is_rot_zoom, br, 1);
                if (is_rot_zoom) {
                    type = 2;
                } else {
                    int is_translation;
                    _obp_br(is_translation, br, 1);
                    type = is_translation ? 1 : 3;
                }
            } else {
                type = 0;
            }
            fh->global_motion_params.gm_type[ref] = type;

            if (type >= 2) {
                ret = _obp_read_global_param(br, fh, type, ref, 2, err);
                if (ret < 0) {
                    return -1;
                }
                ret = _obp_read_global_param(br, fh, type, ref, 3, err);
                if (ret < 0) {
                    return -1;
                }
                if (type == 3) {
                    ret = _obp_read_global_param(br, fh, type, ref, 4, err);
                    if (ret < 0) {
                        return -1;
                    }
                    ret = _obp_read_global_param(br, fh, type, ref, 5, err);
                    if (ret < 0) {
                        return -1;
                    }
                } else {
                    fh->global_motion_params.gm_params[ref][4] = -fh->global_motion_params.gm_params[ref][3];
                    fh->global_motion_params.gm_params[ref][5] = fh->global_motion_params.gm_params[ref][2];
                }
            }
            if (type >= 1) {
                ret = _obp_read_global_param(br, fh, type, ref, 0, err);
                if (ret < 0) {
                    return -1;
                }
                ret = _obp_read_global_param(br, fh, type, ref, 1, err);
                if (ret < 0) {
                    return -1;
                }
            }
        }
    }
    /* film_grain_params() */
    if (!seq->film_grain_params_present || (!fh->show_frame && !fh->showable_frame)) {
        /* reset_grain_params() */
        memset(&fh->film_grain_params, 0, sizeof(fh->film_grain_params));
        /* return */
    } else {
        _obp_br(fh->film_grain_params.apply_grain, br, 1);
        if (!fh->film_grain_params.apply_grain) {
            /* reset_grain_params() */
            memset(&fh->film_grain_params, 0, sizeof(fh->film_grain_params));
            /* return */
        } else {
            _obp_br(fh->film_grain_params.grain_seed, br, 16);
            if (fh->frame_type == OBP_INTER_FRAME) {
                _obp_br(fh->film_grain_params.update_grain, br, 1);
            } else {
                fh->film_grain_params.update_grain = 1;
            }
            if (!fh->film_grain_params.update_grain) {
                _obp_br(fh->film_grain_params.film_grain_params_ref_idx, br, 3);
                uint16_t tempGrainSeed = fh->film_grain_params.grain_seed;
                /* load_grain_params() */
                fh->film_grain_params            = state->RefGrainParams[fh->film_grain_params.film_grain_params_ref_idx];
                fh->film_grain_params.grain_seed = tempGrainSeed;
                /* return */
            } else {
                uint8_t numPosLuma, numPosChroma;
                _obp_br(fh->film_grain_params.num_y_points, br, 4);
                for (uint8_t i = 0; i < fh->film_grain_params.num_y_points; i++) {
                    _obp_br(fh->film_grain_params.point_y_value[i], br, 8);
                    _obp_br(fh->film_grain_params.point_y_scaling[i], br, 8);
                }
                if (seq->color_config.mono_chrome) {
                    fh->film_grain_params.chroma_scaling_from_luma = 0;
                } else {
                    _obp_br(fh->film_grain_params.chroma_scaling_from_luma, br, 1);
                }
                if (seq->color_config.mono_chrome || fh->film_grain_params.chroma_scaling_from_luma ||
                    (seq->color_config.subsampling_x == 1 && seq->color_config.subsampling_y == 1 &&
                     fh->film_grain_params.num_y_points == 0)) {
                     fh->film_grain_params.num_cb_points = 0;
                     fh->film_grain_params.num_cr_points = 0;
                } else {
                    _obp_br(fh->film_grain_params.num_cb_points, br, 4);
                    for (uint8_t i = 0; i < fh->film_grain_params.num_cb_points; i++) {
                        _obp_br(fh->film_grain_params.point_cb_value[i], br, 8);
                        _obp_br(fh->film_grain_params.point_cb_scaling[i], br, 8);
                    }
                    _obp_br(fh->film_grain_params.num_cr_points, br, 4);
                    for (uint8_t i = 0; i < fh->film_grain_params.num_cr_points; i++) {
                        _obp_br(fh->film_grain_params.point_cr_value[i], br, 8);
                        _obp_br(fh->film_grain_params.point_cr_scaling[i], br, 8);
                    }
                }
                _obp_br(fh->film_grain_params.grain_scaling_minus_8, br, 2);
                _obp_br(fh->film_grain_params.ar_coeff_lag, br, 2);
                numPosLuma = 2 * fh->film_grain_params.ar_coeff_lag * (fh->film_grain_params.ar_coeff_lag + 1);
                if (fh->film_grain_params.num_y_points) {
                    numPosChroma = numPosLuma + 1;
                    for (uint8_t i = 0; i < numPosLuma; i++) {
                        _obp_br(fh->film_grain_params.ar_coeffs_y_plus_128[i], br, 8);
                    }
                } else {
                    numPosChroma = numPosLuma;
                }
                if (fh->film_grain_params.chroma_scaling_from_luma || fh->film_grain_params.num_cb_points) {
                    for (uint8_t i = 0; i < numPosChroma; i++) {
                        _obp_br(fh->film_grain_params.ar_coeffs_cb_plus_128[i], br, 8);
                    }
                }
                if (fh->film_grain_params.chroma_scaling_from_luma || fh->film_grain_params.num_cr_points) {
                    for (uint8_t i = 0; i < numPosChroma; i++) {
                        _obp_br(fh->film_grain_params.ar_coeffs_cr_plus_128[i], br, 8);
                    }
                }
                _obp_br(fh->film_grain_params.ar_coeff_shift_minus_6, br, 2);
                _obp_br(fh->film_grain_params.grain_scale_shift, br, 2);
                if (fh->film_grain_params.num_cb_points) {
                    _obp_br(fh->film_grain_params.cb_mult, br, 8);
                    _obp_br(fh->film_grain_params.cb_luma_mult, br, 8);
                    _obp_br(fh->film_grain_params.cb_offset, br, 9);
                }
                if (fh->film_grain_params.num_cr_points) {
                    _obp_br(fh->film_grain_params.cr_mult, br, 8);
                    _obp_br(fh->film_grain_params.cr_luma_mult, br, 8);
                    _obp_br(fh->film_grain_params.cr_offset, br, 9);
                }
                _obp_br(fh->film_grain_params.overlap_flag, br, 1);
                _obp_br(fh->film_grain_params.clip_to_restricted_range, br, 1);
            }
        }
    }

    /* Stash refs for future frame use. */
    /* decode_frame_wrapup() */
    for (int i = 0; i < 8; i++) {
        if ((fh->refresh_frame_flags >> i) & 1) {
            state->RefOrderHint[i]     = fh->order_hint;
            state->RefFrameType[i]     = fh->frame_type;
            state->RefUpscaledWidth[i] = UpscaledWidth;
            state->RefFrameHeight[i]   = FrameHeight;
            state->RefRenderWidth[i]   = fh->RenderWidth;
            state->RefRenderHeight[i]  = fh->RenderHeight;
            state->RefFrameId[i]       = fh->current_frame_id;
            state->RefGrainParams[i]   = fh->film_grain_params;
            /* save_grain_params() */
            for (int j = 0; j < 8; j++) {
                for (int k = 0; k < 6; k++) {
                    state->SavedGmParams[i][j][k] = fh->global_motion_params.gm_params[j][k];
                }
            }
            /* save_segmentation_params() */
            for (int j = 0; j < 8; j++) {
                for (int k = 0; k < 8; k++) {
                    state->SavedFeatureEnabled[i][j][k] = FeatureEnabled[j][k];
                    state->SavedFeatureData[i][j][k]    = FeatureData[j][k];
                }
            }
            /* save_loop_filter_params() */
            for (int j = 0; j < 8; j++) {
                state->SavedLoopFilterRefDeltas[i][j]  = fh->loop_filter_params.loop_filter_ref_deltas[j];
                state->SavedLoopFilterModeDeltas[i][j] = fh->loop_filter_params.loop_filter_mode_deltas[j];
            }
        }
    }

    /* Handle show_existing_frame semantics. */
    /* decode_frame_wrapup() */
    if (fh->show_existing_frame && fh->frame_type == OBP_KEY_FRAME) {
        fh->order_hint = state->RefOrderHint[fh->frame_to_show_map_idx];
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 6; j++) {
                fh->global_motion_params.gm_params[i][j] = state->SavedGmParams[fh->frame_to_show_map_idx][i][j];
            }
        }
    }
    if (fh->show_existing_frame) {
        *SeenFrameHeader = 0;
        state->prev_filled = 0;
    } else {
        state->prev = *fh;
        state->prev_filled = 1;
    }

    /* Stash byte position for use in OBU_FRAME parsing. */
    _obp_br_byte_alignment(br);
    state->frame_header_end_pos = _obp_br_get_pos(br);

    return 0;
}
