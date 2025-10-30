#ifndef LIMITER_H
#define LIMITER_H

#include <opus/opus.h>
#include <stdlib.h>
#include <math.h>

/* Constants for the audio limiter */
#define K_SUB_FRAMES_IN_FRAME 20
#define K_INITIAL_FILTER_STATE_LEVEL 0.0f
/* Instant attack. */
#define K_ATTACK_FILTER_CONSTANT 0.0f
/* This constant affects the way scaling factors are interpolated for the first
 * sub-frame of a frame. Only in the case in which the first sub-frame has an
 * estimated level which is greater than the that of the previous analyzed
 * sub-frame, linear interpolation is replaced with a power function which
 * reduces the chances of over-shooting (and hence saturation), however reducing
 * the fixed gain effectiveness.
 */
#define K_ATTACK_FIRST_SUB_FRAME_INTERPOLATION_POWER 8.0f
/* Limiter decay constant.
 * Computed as `10 ** (-1/20 * SUBFRAME_DURATION / K_DECAY_MS)` where:
 * - `SUBFRAME_DURATION` is `K_FRAME_DURATION_MS / K_SUB_FRAMES_IN_FRAME`;
 * - `K_FRAME_DURATION_MS` is 10 ms.;
 * - `K_DECAY_MS` is 20.0f;
 */
#define K_DECAY_FILTER_CONSTANT 0.9971259f
/* Number of interpolation points for each region of the limiter.
 * These values have been tuned to limit the interpolated gain curve error given
 * the limiter parameters and allowing a maximum error of +/- 32768^-1.
 */
#define K_INTERPOLATED_GAIN_CURVE_KNEE_POINTS 22
#define K_INTERPOLATED_GAIN_CURVE_BEYOND_KNEE_POINTS 10
#define K_INTERPOLATED_GAIN_CURVE_TOTAL_POINTS (K_INTERPOLATED_GAIN_CURVE_KNEE_POINTS + K_INTERPOLATED_GAIN_CURVE_BEYOND_KNEE_POINTS)
/* Defined as DbfsToLinear(kLimiterMaxInputLevelDbFs) */
#define K_MAX_INPUT_LEVEL_LINEAR 36766.300710566735f

void compute_scaling_factors(
    opus_int32 *buffer,
    float envelope[K_SUB_FRAMES_IN_FRAME],
    float scaling_factors[K_SUB_FRAMES_IN_FRAME + 1],
    float *per_sample_scaling_factors,
    int samples_in_sub_frame,
    float *filter_state_level,
    float *last_scaling_factor);

void init_limiter(void);
void init_limiter_avx2(void);
void init_limiter_sse42(void);
void init_limiter_scalar(void);

void scale_buffer(
    opus_int32 *buffer,
    int samples,
    float *per_sample_scaling_factors,
    opus_int16 *outBuffer);

void clamp_buffer(opus_int32 *buffer, int samples, opus_int16 *outBuffer);
#endif /* LIMITER_H */