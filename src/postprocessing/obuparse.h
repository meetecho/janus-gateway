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

#ifndef OBUPARSE_H
#define OBUPARSE_H

#include <stddef.h>
#include <stdint.h>

/*********************************************
 * Various enums from the AV1 specification. *
 *********************************************/

/*
 * OBU types.
 */
typedef enum {
    /* 0 Reserved */
    OBP_OBU_SEQUENCE_HEADER = 1,
    OBP_OBU_TEMPORAL_DELIMITER = 2,
    OBP_OBU_FRAME_HEADER = 3,
    OBP_OBU_TILE_GROUP = 4,
    OBP_OBU_METADATA = 5,
    OBP_OBU_FRAME = 6,
    OBP_OBU_REDUNDANT_FRAME_HEADER = 7,
    OBP_OBU_TILE_LIST = 8,
    /* 9-14 Reserved */
    OBP_OBU_PADDING = 15
} OBPOBUType;

/*
 * Metadata types for the Metadata OBU.
 */
typedef enum {
    /* 0 Reserved */
    OBP_METADATA_TYPE_HDR_CLL = 1,
    OBP_METADATA_TYPE_HDR_MDCV = 2,
    OBP_METADATA_TYPE_SCALABILITY = 3,
    OBP_METADATA_TYPE_ITUT_T35 = 4,
    OBP_METADATA_TYPE_TIMECODE = 5
    /* 6-31 Unregistered user private */
    /* 32 and greater Reserved for AOM use */
} OBPMetadataType;

/*
 * Color primaries.
 *
 * These match ISO/IEC 23091-4/ITU-T H.273.
 */
typedef enum {
    OBP_CP_BT_709 = 1,
    OBP_CP_UNSPECIFIED = 2,
    OBP_CP_BT_470_M = 4,
    OBP_CP_BT_470_B_G = 5,
    OBP_CP_BT_601 = 6,
    OBP_CP_SMPTE_240 = 7,
    OBP_CP_GENERIC_FILM = 8,
    OBP_CP_BT_2020 = 9,
    OBP_CP_XYZ = 10,
    OBP_CP_SMPTE_431 = 11,
    OBP_CP_SMPTE_432 = 12,
    OBP_CP_EBU_3213 = 22
} OBPColorPrimaries;

/*
 * Transfer characteristics.
 *
 * These match ISO/IEC 23091-4/ITU-T H.273.
 */
typedef enum {
    OBP_TC_RESERVED_0 = 0,
    OBP_TC_BT_709 = 1,
    OBP_TC_UNSPECIFIED = 2,
    OBP_TC_RESERVED_3 = 3,
    OBP_TC_BT_470_M = 4,
    OBP_TC_BT_470_B_G = 5,
    OBP_TC_BT_601 = 6,
    OBP_TC_SMPTE_240 = 7,
    OBP_TC_LINEAR = 8,
    OBP_TC_LOG_100 = 9,
    OBP_TC_LOG_100_SQRT10 = 10,
    OBP_TC_IEC_61966 = 11,
    OBP_TC_BT_1361 = 12,
    OBP_TC_SRGB = 13,
    OBP_TC_BT_2020_10_BIT = 14,
    OBP_TC_BT_2020_12_BIT = 15,
    OBP_TC_SMPTE_2084 = 16,
    OBP_TC_SMPTE_428 = 17,
    OBP_TC_HLG = 18
} OBPTransferCharacteristics;

/*
 * Color matrix coefficients.
 *
 * These match ISO/IEC 23091-4/ITU-T H.273.
 */
typedef enum {
    OBP_MC_IDENTITY = 0,
    OBP_MC_BT_709 = 1,
    OBP_MC_UNSPECIFIED = 2,
    OBP_MC_RESERVED_3 = 3,
    OBP_MC_FCC = 4,
    OBP_MC_BT_470_B_G = 5,
    OBP_MC_BT_601 = 6,
    OBP_MC_SMPTE_240 = 7,
    OBP_MC_SMPTE_YCGCO = 8,
    OBP_MC_BT_2020_NCL = 9,
    OBP_MC_BT_2020_CL = 10,
    OBP_MC_SMPTE_2085 = 11,
    OBP_MC_CHROMAT_NCL = 12,
    OBP_MC_CHROMAT_CL = 13,
    OBP_MC_ICTCP = 14
} OBPMatrixCoefficients;

/*
 * Chroma sample position.
 */
typedef enum {
    OBP_CSP_UNKNOWN = 0,
    OBP_CSP_VERTICAL = 1,
    OBP_CSP_COLOCATED = 2
    /* 3 Reserved */
} OBPChromaSamplePosition;

/*
 * Frame types.
 */
typedef enum {
    OBP_KEY_FRAME = 0,
    OBP_INTER_FRAME = 1,
    OBP_INTRA_ONLY_FRAME = 2,
    OBP_SWITCH_FRAME = 3
} OBPFrameType;

/**************************************************
 * Various structures from the AV1 specification. *
 **************************************************/

/*
 * Sequence Header OBU
 */
typedef struct OBPSequenceHeader {
    uint8_t seq_profile;
    int still_picture;
    int reduced_still_picture_header;
    int timing_info_present_flag;
    struct {
        uint32_t num_units_in_display_tick;
        uint32_t time_scale;
        int equal_picture_interval;
        uint32_t num_ticks_per_picture_minus_1;
    } timing_info;
    int decoder_model_info_present_flag;
    struct {
        uint8_t buffer_delay_length_minus_1;
        uint32_t num_units_in_decoding_tick;
        uint8_t buffer_removal_time_length_minus_1;
        uint8_t frame_presentation_time_length_minus_1;
    } decoder_model_info;
    int initial_display_delay_present_flag;
    uint8_t operating_points_cnt_minus_1;
    uint8_t operating_point_idc[32];
    uint8_t seq_level_idx[32];
    uint8_t seq_tier[32];
    int decoder_model_present_for_this_op[32];
    struct {
        uint64_t decoder_buffer_delay;
        uint64_t encoder_buffer_delay;
        int low_delay_mode_flag;
    } operating_parameters_info[32];
    int initial_display_delay_present_for_this_op[32];
    uint8_t initial_display_delay_minus_1[32];
    uint8_t frame_width_bits_minus_1;
    uint8_t frame_height_bits_minus_1;
    uint32_t max_frame_width_minus_1;
    uint32_t max_frame_height_minus_1;
    int frame_id_numbers_present_flag;
    uint8_t delta_frame_id_length_minus_2;
    uint8_t additional_frame_id_length_minus_1;
    int use_128x128_superblock;
    int enable_filter_intra;
    int enable_intra_edge_filter;
    int enable_interintra_compound;
    int enable_masked_compound;
    int enable_warped_motion;
    int enable_dual_filter;
    int enable_order_hint;
    int enable_jnt_comp;
    int enable_ref_frame_mvs;
    int seq_choose_screen_content_tools;
    int seq_force_screen_content_tools;
    int seq_choose_integer_mv;
    int seq_force_integer_mv;
    uint8_t order_hint_bits_minus_1;
    uint8_t OrderHintBits;
    int enable_superres;
    int enable_cdef;
    int enable_restoration;
    struct {
        int high_bitdepth;
        int twelve_bit;
        uint8_t BitDepth;
        int mono_chrome;
        uint8_t NumPlanes;
        int color_description_present_flag;
        OBPColorPrimaries color_primaries;
        OBPTransferCharacteristics transfer_characteristics;
        OBPMatrixCoefficients matrix_coefficients;
        int color_range;
        int subsampling_x;
        int subsampling_y;
        OBPChromaSamplePosition chroma_sample_position;
        int separate_uv_delta_q;
    } color_config;
    int film_grain_params_present;
} OBPSequenceHeader;

/*
 * Film Grain Parameters.
 */
typedef struct OBPFilmGrainParameters {
    int apply_grain;
    uint16_t grain_seed;
    int update_grain;
    uint8_t film_grain_params_ref_idx;
    uint8_t num_y_points;
    uint8_t point_y_value[16];
    uint8_t point_y_scaling[16];
    int chroma_scaling_from_luma;
    uint8_t num_cb_points;
    uint8_t point_cb_value[16];
    uint8_t point_cb_scaling[16];
    uint8_t num_cr_points;
    uint8_t point_cr_value[16];
    uint8_t point_cr_scaling[16];
    uint8_t grain_scaling_minus_8;
    uint8_t ar_coeff_lag;
    uint8_t ar_coeffs_y_plus_128[24];
    uint8_t ar_coeffs_cb_plus_128[25];
    uint8_t ar_coeffs_cr_plus_128[25];
    uint8_t ar_coeff_shift_minus_6;
    uint8_t grain_scale_shift;
    uint8_t cb_mult;
    uint8_t cb_luma_mult;
    uint16_t cb_offset;
    uint8_t cr_mult;
    uint8_t cr_luma_mult;
    uint16_t cr_offset;
    int overlap_flag;
    int clip_to_restricted_range;
} OBPFilmGrainParameters;

/*
 * Frame Header OBU
 */
typedef struct OBPFrameHeader {
    int show_existing_frame;
    uint8_t frame_to_show_map_idx;
    struct {
        uint32_t frame_presentation_time;
    } temporal_point_info;
    uint32_t display_frame_id;
    /* load_grain_params() unimplemented. */
    OBPFrameType frame_type;
    int show_frame;
    int showable_frame;
    int error_resilient_mode;
    int disable_cdf_update;
    int allow_screen_content_tools;
    int force_integer_mv;
    uint32_t current_frame_id;
    int frame_size_override_flag;
    uint8_t order_hint;
    uint8_t primary_ref_frame;
    int buffer_removal_time_present_flag;
    uint32_t buffer_removal_time[32];
    uint8_t refresh_frame_flags;
    uint8_t ref_order_hint[8];
    uint32_t frame_width_minus_1;
    uint32_t frame_height_minus_1;
    struct {
        int use_superres;
        uint8_t coded_denom;
    } superres_params;
    int render_and_frame_size_different;
    uint16_t render_width_minus_1;
    uint16_t render_height_minus_1;
    uint32_t RenderWidth;
    uint32_t RenderHeight;
    int allow_intrabc;
    int frame_refs_short_signaling;
    uint8_t last_frame_idx;
    uint8_t gold_frame_idx;
    uint8_t ref_frame_idx[7];
    uint8_t delta_frame_id_minus_1[7];
    int found_ref;
    int allow_high_precision_mv;
    struct {
        int is_filter_switchable;
        uint8_t interpolation_filter;
    } interpolation_filter;
    int is_motion_mode_switchable;
    int use_ref_frame_mvs;
    int disable_frame_end_update_cdf;
    struct {
        int uniform_tile_spacing_flag;
        uint16_t TileRows;
        uint16_t TileCols;
        uint32_t context_update_tile_id;
        uint8_t tile_size_bytes_minus_1;
    } tile_info;
    struct {
        uint8_t base_q_idx;
        int diff_uv_delta;
        int using_qmatrix;
        uint8_t qm_y;
        uint8_t qm_u;
        uint8_t qm_v;
    } quantization_params;
    struct {
        int segmentation_enabled;
        int segmentation_update_map;
        int segmentation_temporal_update;
        int segmentation_update_data;
    } segmentation_params;
    struct {
        int delta_q_present;
        uint8_t delta_q_res;
    } delta_q_params;
    struct {
        int delta_lf_present;
        uint8_t delta_lf_res;
        int delta_lf_multi;
    } delta_lf_params;
    struct {
        uint8_t loop_filter_level[4];
        uint8_t loop_filter_sharpness;
        int loop_filter_delta_enabled;
        int loop_filter_delta_update;
        int update_ref_delta[8];
        int8_t loop_filter_ref_deltas[8];
        int update_mode_delta[8];
        int8_t loop_filter_mode_deltas[8];
    } loop_filter_params;
    struct {
        uint8_t cdef_damping_minus_3;
        uint8_t cdef_bits;
        uint8_t cdef_y_pri_strength[8];
        uint8_t cdef_y_sec_strength[8];
        uint8_t cdef_uv_pri_strength[8];
        uint8_t cdef_uv_sec_strength[8];
    } cdef_params;
    struct {
        uint8_t lr_type[3];
        uint8_t lr_unit_shift;
        int lr_uv_shift;
    } lr_params;
    int tx_mode_select;
    int skip_mode_present;
    int reference_select;
    int allow_warped_motion;
    int reduced_tx_set;
    struct {
        uint8_t gm_type[8];
        int32_t gm_params[8][6];
        uint32_t prev_gm_params[8][6];
    } global_motion_params;
    OBPFilmGrainParameters film_grain_params;
} OBPFrameHeader;

/*
 * Tile Group OBU.
 */
typedef struct OBPTileGroup {
    uint16_t NumTiles;
    int tile_start_and_end_present_flag;
    uint16_t tg_start;
    uint16_t tg_end;
    uint64_t TileSize[4096];
} OBPTileGroup;

/*
 * Tile List OBU
 */
typedef struct OBPTileList {
    uint8_t output_frame_width_in_tiles_minus_1;
    uint8_t output_frame_height_in_tiles_minus_1;
    uint16_t tile_count_minus_1;
    struct {
        uint8_t anchor_frame_idx;
        uint8_t anchor_tile_row;
        uint8_t anchor_tile_col;
        uint16_t tile_data_size_minus_1;
        uint8_t *coded_tile_data;
        size_t coded_tile_data_size;
    } tile_list_entry[65536];
} OBPTileList;

/*
 * Metadata OBU
 */
typedef struct OBPMetadata {
    OBPMetadataType metadata_type;
    struct {
        uint8_t itu_t_t35_country_code; /* Annex A of Recommendation ITU-T T.35. */
        uint8_t itu_t_t35_country_code_extension_byte;
        uint8_t *itu_t_t35_payload_bytes;
        size_t itu_t_t35_payload_bytes_size;
    } metadata_itut_t35;
    struct {
        uint16_t max_cll;
        uint16_t max_fall;
    } metadata_hdr_cll;
    struct {
        uint16_t primary_chromaticity_x[3];
        uint16_t primary_chromaticity_y[3];
        uint16_t white_point_chromaticity_x;
        uint16_t white_point_chromaticity_y;
        uint32_t luminance_max;
        uint32_t luminance_min;
    } metadata_hdr_mdcv;
    struct {
        uint8_t scalability_mode_idc;
        struct {
            uint8_t spatial_layers_cnt_minus_1;
            int spatial_layer_dimensions_present_flag;
            int spatial_layer_description_present_flag;
            int temporal_group_description_present_flag;
            uint8_t scalability_structure_reserved_3bits;
            uint16_t spatial_layer_max_width[3];
            uint16_t spatial_layer_max_height[3];
            uint8_t spatial_layer_ref_id[3];
            uint8_t temporal_group_size;
            uint8_t temporal_group_temporal_id[256];
            int temporal_group_temporal_switching_up_point_flag[256];
            int temporal_group_spatial_switching_up_point_flag[256];
            uint8_t temporal_group_ref_cnt[256];
            uint8_t temporal_group_ref_pic_diff[256][8];
        } scalability_structure;
    } metadata_scalability;
    struct {
        uint8_t counting_type;
        int full_timestamp_flag;
        int discontinuity_flag;
        int cnt_dropped_flag;
        uint16_t n_frames;
        uint8_t seconds_value;
        uint8_t minutes_value;
        uint8_t hours_value;
        int seconds_flag;
        int minutes_flag;
        int hours_flag;
        uint8_t time_offset_length;
        uint32_t time_offset_value;
    } metadata_timecode;
    struct {
        uint8_t *buf;
        size_t buf_size;
    } unregistered;
} OBPMetadata;

/*******************
 * API structures. *
 *******************/

/*
 * OBPError contains a user-provided buffer and buffer size
 * where obuparse can write error messages to.
 */
typedef struct OBPError {
    char *error;
    size_t size;
} OBPError;

/***************************
 * Private API Structures. *
 ***************************/

 /*
  * Various bits of state required for parsing uncompressed_header(), such as reference
  * management.
  *
  * Do not touch the values of these members. They are for internal obuparser use only.
  */
 typedef struct OBPState {
     /* Redundant Frame Header things. */
     OBPFrameHeader prev;
     int prev_filled;

     /* For use only on OBU_FRAME parsing. */
     size_t frame_header_end_pos;

     /* Frame state. */
     OBPFrameType RefFrameType[8];
     uint8_t RefValid[8];
     uint8_t RefOrderHint[8];
     uint8_t OrderHint[8];
     uint8_t RefFrameId[8];
     uint32_t RefUpscaledWidth[8];
     uint32_t RefFrameHeight[8];
     uint32_t RefRenderWidth[8];
     uint32_t RefRenderHeight[8];
     int32_t RefFrameSignBias[8];
     OBPFilmGrainParameters RefGrainParams[8];
     uint8_t order_hint;
     uint32_t SavedGmParams[8][8][6];
     int SavedFeatureEnabled[8][8][8];
     int16_t SavedFeatureData[8][8][8];
     int8_t SavedLoopFilterRefDeltas[8][8];
     int8_t SavedLoopFilterModeDeltas[8][8];
 } OBPState;

/******************
 * API functions. *
 ******************/

/*
 * obp_get_next_obu parses the next OBU header in a packet containing a set of one or more OBUs
 * (e.g. an IVF or ISOBMFF packet) and returns its location in the buffer, as well as all
 * relevant data from the header.
 *
 * Input:
 *     buf      - Input packet buffer.
 *     buf_size - Size of the input packet buffer.
 *     err      - An error buffer and buffer size to write any error messages into.
 *
 * Output:
 *     obu_type    - The type of OBU.
 *     offset      - The offset into the buffer where this OBU starts, excluding the OBU header.
 *     obu_size    - The size of the OBU, excluding the size of the OBU header.
 *     temporal_id - The temporal ID of the OBU.
 *     spatial_id  - The spatial ID of the OBU.
 *
 * Returns:
 *     0 on success, -1 on error.
 */
int obp_get_next_obu(uint8_t *buf, size_t buf_size, OBPOBUType *obu_type, ptrdiff_t *offset,
                     size_t *obu_size, int *temporal_id, int *spatial_id, OBPError *err);

/*
 * obp_parse_sequence_header parses a sequence header OBU and fills out the fields in a
 * user-provided OBPSequenceHeader structure.
 *
 * Input:
 *     buf      - Input OBU buffer. This is expected to *NOT* contain the OBU header.
 *     buf_size - Size of the input OBU buffer.
 *     err      - An error buffer and buffer size to write any error messages into.
 *
 * Output:
 *     seq_header - A user provided structure that will be filled in with all the parsed data.
 *
 * Returns:
 *     0 on success, -1 on error.
 */
int obp_parse_sequence_header(uint8_t *buf, size_t buf_size, OBPSequenceHeader *seq_header, OBPError *err);

/*
 * obp_parse_frame_header parses a frame header OBU and fills out the fields in a user-provided
 * OBPFrameHeader structure.
 *
 * Input:
 *     buf          - Input OBU buffer. This is expected to *NOT* contain the OBU header.
 *     buf_size     - Size of the input OBU buffer.
 *     state        - An opaque state structure. Must be zeroed by the user on first use.
 *     temporal_id  - A temporal ID previously obtained from obu_parse_sequence header.
 *     spatial_id   - A spatial ID previously obtained from obu_parse_sequence header.
 *     err          - An error buffer and buffer size to write any error messages into.
 *
 * Output:
 *     frame_header    - A user provided structure that will be filled in with all the parsed data.
 *     SeenFrameHeader - Whether or not a frame header has beee seen. Tracking variable as per AV1 spec.
 *
 * Returns:
 *     0 on success, -1 on error.
 */
int obp_parse_frame_header(uint8_t *buf, size_t buf_size, OBPSequenceHeader *seq_header, OBPState *state,
                           int temporal_id, int spatial_id, OBPFrameHeader *frame_header, int *SeenFrameHeader, OBPError *err);

/*
 * obp_parse_frame parses a frame OBU and fills out the fields in user-provided OBPFrameHeader
 * and OBPTileGroup structures.
 *
 * Input:
 *     buf          - Input OBU buffer. This is expected to *NOT* contain the OBU header.
 *     buf_size     - Size of the input OBU buffer.
 *     state        - An opaque state structure. Must be zeroed by the user on first use.
 *     temporal_id  - A temporal ID previously obtained from obu_parse_sequence header.
 *     spatial_id   - A spatial ID previously obtained from obu_parse_sequence header.
 *     err          - An error buffer and buffer size to write any error messages into.
 *
 * Output:
 *     frame_header    - A user provided structure that will be filled in with all the parsed data.
 *     tile_group      - A user provided structure that will be filled in with all the parsed data.
 *     SeenFrameHeader - Whether or not a frame header has been seen. Tracking variable as per AV1 spec.
 *
 * Returns:
 *     0 on success, -1 on error.
 */
int obp_parse_frame(uint8_t *buf, size_t buf_size, OBPSequenceHeader *seq_header, OBPState *state,
                    int temporal_id, int spatial_id, OBPFrameHeader *frame_header, OBPTileGroup *tile_group,
                    int *SeenFrameHeader, OBPError *err);

/*
 * obp_parse_tile_group parses a tile group OBU and fills out the fields in a
 * user-provided OBPTileGroup structure.
 *
 * Input:
 *     buf          - Input OBU buffer. This is expected to *NOT* contain the OBU header.
 *     buf_size     - Size of the input OBU buffer.
 *     frame_header - A filled in frame header OBU previously seen.
 *     err          - An error buffer and buffer size to write any error messages into.
 *
 * Output:
 *     tile_group      - A user provided structure that will be filled in with all the parsed data.
 *     SeenFrameHeader - Whether or not a frame header has been seen. Tracking variable as per AV1 spec.
 *
 * Returns:
 *     0 on success, -1 on error.
 */
int obp_parse_tile_group(uint8_t *buf, size_t buf_size, OBPFrameHeader *frame_header, OBPTileGroup *tile_group,
                         int *SeenFrameHeader, OBPError *err);

/*
 * obp_parse_metadata parses a metadata OBU and fills out the fields in a user-provided OBPMetadata
 * structure. This OBU's returned payload is *NOT* safe to use once the user-provided 'buf' has
 * been freed, since it may fill the structure with pointers to offsets in that data.
 *
 * Input:
 *     buf      - Input OBU buffer. This is expected to *NOT* contain the OBU header.
 *     buf_size - Size of the input OBU buffer.
 *     err      - An error buffer and buffer size to write any error messages into.
 *
 * Output:
 *     metadata - A user provided structure that will be filled in with all the parsed data.
 *
 * Returns:
 *     0 on success, -1 on error.
 */
int obp_parse_metadata(uint8_t *buf, size_t buf_size, OBPMetadata *metadata, OBPError *err);

/*
 * obp_parse_tile_list parses a tile list OBU and fills out the fields in a user-provided OBPTileList
 * structure. This OBU's returned payload is *NOT* safe to use once the user-provided 'buf' has
 * been freed, since it may fill the structure with pointers to offsets in that data.
 *
 * Input:
 *     buf      - Input OBU buffer. This is expected to *NOT* contain the OBU header.
 *     buf_size - Size of the input OBU buffer.
 *     err      - An error buffer and buffer size to write any error messages into.
 *
 * Output:
 *     tile_list - A user provided structure that will be filled in with all the parsed data.
 *
 * Returns:
 *     0 on success, -1 on error.
 */
int obp_parse_tile_list(uint8_t *buf, size_t buf_size, OBPTileList *tile_list, OBPError *err);

#endif
