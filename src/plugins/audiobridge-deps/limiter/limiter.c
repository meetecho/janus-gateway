#include "limiter.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../../debug.h"

/* SIMD intrinsics */
#if defined(__AVX2__) || defined(__SSE4_2__)
#include <immintrin.h>
#include <cpuid.h>

static int has_avx2(void) {
    unsigned int eax, ebx, ecx, edx;
    /* 1. CPUID leaf 1: AVX + OSXSAVE */
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx))
        return 0;

    if (!(ecx & bit_AVX))
        return 0;

    if (!(ecx & bit_OSXSAVE))
        return 0;

    /* 2. Check tath OS saves XMM/YMM */
    unsigned long long xcr0 = __builtin_ia32_xgetbv(0);
    if ((xcr0 & 0x6) != 0x6)
        return 0;

    /* 3. CPUID leaf 7 subleaf 0: AVX2 */
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx))
        return 0;

    /* AVX2 — bit 5 of EBX */
    return (ebx & (1u << 5)) != 0;
}
static int has_sse42(void) {
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & (1u << 20)) != 0;  /* SSE4.2 — bit 20 of ECX */
    }
    return 0;
}
#endif

/* Static data for the limiter */
static float approximation_params_x[K_INTERPOLATED_GAIN_CURVE_TOTAL_POINTS] = {
	30057.296875f,    30148.986328125f, 30240.67578125f,  30424.052734375f,
	30607.4296875f,   30790.806640625f, 30974.18359375f,  31157.560546875f,
	31340.939453125f, 31524.31640625f,  31707.693359375f, 31891.0703125f,
	32074.447265625f, 32257.82421875f,  32441.201171875f, 32624.580078125f,
	32807.95703125f,  32991.33203125f,  33174.7109375f,   33358.08984375f,
	33541.46484375f,  33724.84375f,     33819.53515625f,  34009.5390625f,
	34200.05859375f,  34389.81640625f,  34674.48828125f,  35054.375f,
	35434.86328125f,  35814.81640625f,  36195.16796875f,  36575.03125f
};

static float approximation_params_m[K_INTERPOLATED_GAIN_CURVE_TOTAL_POINTS] = {
	-3.515235675877192989e-07f, -1.050251626111275982e-06f,
	-2.085213736791047268e-06f, -3.443004743530764244e-06f,
	-4.773849468620028347e-06f, -6.077375928725814447e-06f,
	-7.353257842623861507e-06f, -8.601219633419532329e-06f,
	-9.821013009059242904e-06f, -1.101243378798244521e-05f,
	-1.217532644659513608e-05f, -1.330956911260727793e-05f,
	-1.441507538402220234e-05f, -1.549179251014720649e-05f,
	-1.653970684856176376e-05f, -1.755882840370759368e-05f,
	-1.854918446042574942e-05f, -1.951086778717581183e-05f,
	-2.044398024736437947e-05f, -2.1348627342376858e-05f,
	-2.222496914328075945e-05f, -2.265374678245279938e-05f,
	-2.242570917587727308e-05f, -2.220122041762806475e-05f,
	-2.19802095671184361e-05f,  -2.176260204578284174e-05f,
	-2.133731686626560986e-05f, -2.092481918225530535e-05f,
	-2.052459603874012828e-05f, -2.013615448959171772e-05f,
	-1.975903069251216948e-05f, -1.939277899509761482e-05f
};

static float approximation_params_q[K_INTERPOLATED_GAIN_CURVE_TOTAL_POINTS] = {
	1.010565876960754395f, 1.031631827354431152f, 1.062929749488830566f,
	1.104239225387573242f, 1.144973039627075195f, 1.185109615325927734f,
	1.224629044532775879f, 1.263512492179870605f, 1.301741957664489746f,
	1.339300632476806641f, 1.376173257827758789f, 1.412345528602600098f,
	1.447803974151611328f, 1.482536554336547852f, 1.516532182693481445f,
	1.549780607223510742f, 1.582272171974182129f, 1.613999366760253906f,
	1.644955039024353027f, 1.675132393836975098f, 1.704526185989379883f,
	1.718986630439758301f, 1.711274504661560059f, 1.703639745712280273f,
	1.696081161499023438f, 1.688597679138183594f, 1.673851132392883301f,
	1.659391283988952637f, 1.645209431648254395f, 1.631297469139099121f,
	1.617647409439086914f, 1.604251742362976074f
};

/* Function pointers for the selected implementation */
static void (*compute_max_envelope_func)(opus_int32 *buffer, float envelope[K_SUB_FRAMES_IN_FRAME], int samples_in_sub_frame) = NULL;
static void (*calculate_scaling_factors_func)(float envelope[K_SUB_FRAMES_IN_FRAME], float scaling_factors[K_SUB_FRAMES_IN_FRAME + 1], float *last_scaling_factor) = NULL;
static void (*compute_per_sample_scaling_factors_func)(float scaling_factors[K_SUB_FRAMES_IN_FRAME + 1], float *per_sample_scaling_factors, int samples_in_sub_frame) = NULL;
static void (*scale_buffer_func)(opus_int32 *buffer, int samples, float *per_sample_scaling_factors, opus_int16 *outBuffer) = NULL;
static void (*clamp_buffer_func)(opus_int32 *buffer, int samples, opus_int16 *outBuffer) = NULL;

#if defined(__AVX2__)
static void compute_max_envelope_avx2(opus_int32 *buffer, float envelope[K_SUB_FRAMES_IN_FRAME], int samples_in_sub_frame){
   /* Compute max envelope without smoothing. */
   int sub_frame, sample_in_sub_frame;
    /* AVX2 implementation - process 8 32-bit integers at a time */
    for (sub_frame = 0; sub_frame < K_SUB_FRAMES_IN_FRAME; ++sub_frame) {
        const opus_int32 *sub_frame_buffer = &buffer[sub_frame * samples_in_sub_frame];
        __m256i max_val = _mm256_setzero_si256();

        /* Process 8 integers at a time */
        int simd_samples = (samples_in_sub_frame / 8) * 8;
        for (sample_in_sub_frame = 0; sample_in_sub_frame < simd_samples; sample_in_sub_frame += 8) {
            __m256i vals = _mm256_loadu_si256((__m256i*)&sub_frame_buffer[sample_in_sub_frame]);
            __m256i abs_vals = _mm256_abs_epi32(vals);
            max_val = _mm256_max_epi32(max_val, abs_vals);
        }

        /* Extract maximum from the vector */
        /* Get max of first 4 and last 4 elements */
        __m128i max_low = _mm256_extracti128_si256(max_val, 0);
        __m128i max_high = _mm256_extracti128_si256(max_val, 1);
        __m128i max_4 = _mm_max_epi32(max_low, max_high);

        /* Get max of first 2 and last 2 elements */
        __m128i max_2 = _mm_max_epi32(max_4, _mm_shuffle_epi32(max_4, _MM_SHUFFLE(1, 0, 3, 2)));

        /* Get max of first and last elements */
        __m128i max_1 = _mm_max_epi32(max_2, _mm_shuffle_epi32(max_2, _MM_SHUFFLE(0, 0, 0, 1)));

        int max_scalar = _mm_cvtsi128_si32(max_1);

        /* Process remaining samples */
        for (; sample_in_sub_frame < samples_in_sub_frame; ++sample_in_sub_frame) {
            int abs_val = abs(sub_frame_buffer[sample_in_sub_frame]);
            if (abs_val > max_scalar) {
                max_scalar = abs_val;
            }
        }

        if ((float)max_scalar > envelope[sub_frame]) {
            envelope[sub_frame] = (float)max_scalar;
        }
    }
}
static void calculate_scaling_factors_avx2(
    float envelope[K_SUB_FRAMES_IN_FRAME],
    float scaling_factors[K_SUB_FRAMES_IN_FRAME + 1],
    float *last_scaling_factor) {
    int i;
    scaling_factors[0] = *last_scaling_factor;

    /* Constants for vectorized operations */
    const __m256 ones = _mm256_set1_ps(1.0f);
    const __m256 threshold_low = _mm256_set1_ps(approximation_params_x[0]);
    const __m256 threshold_high = _mm256_set1_ps(K_MAX_INPUT_LEVEL_LINEAR);
    const __m256 scale_factor = _mm256_set1_ps(32768.0f);

    /* Process 8 elements at a time */
    for (i = 0; i + 8 <= K_SUB_FRAMES_IN_FRAME; i += 8) {
        /* Load 8 input levels */
        __m256 input_levels = _mm256_loadu_ps(&envelope[i]);

        /* Create masks for the three conditions */
        __m256 mask_low = _mm256_cmp_ps(input_levels, threshold_low, _CMP_LE_OQ);
        __m256 mask_high = _mm256_cmp_ps(input_levels, threshold_high, _CMP_GE_OQ);
        __m256 mask_mid = _mm256_andnot_ps(mask_low, _mm256_andnot_ps(mask_high, ones));

        /* Calculate scaling factors for each case */
        /* Case 1: input_level <= approximation_params_x[0] -> scaling factor = 1.0f */
        __m256 result_low = ones;

        /* Case 2: input_level >= K_MAX_INPUT_LEVEL_LINEAR -> scaling factor = 32768.f / input_level */
        __m256 result_high = _mm256_div_ps(scale_factor, input_levels);

        /* Case 3: Middle region - use scalar processing for binary search */
        __m256 result_mid = _mm256_setzero_ps();

        /* Handle middle region with scalar code (binary search cannot be easily vectorized) */
        float temp_input[8];
        float temp_result[8];
        _mm256_storeu_ps(temp_input, input_levels);
        _mm256_storeu_ps(temp_result, result_mid);

        for (int j = 0; j < 8; j++) {
            if (((float*)&mask_mid)[j] != 0.0f) {  /* Check if mask is set for this element */
                const float input_level = temp_input[j];
                /* Knee and limiter regions; find the linear piece index. Searching in [0, K_INTERPOLATED_GAIN_CURVE_TOTAL_POINTS) */
                int left = 0;
                int right = K_INTERPOLATED_GAIN_CURVE_TOTAL_POINTS;
                while (left < right) {
                    int mid = left + (right - left) / 2;
                    if (approximation_params_x[mid] < input_level)
                        left = mid + 1;
                    else
                        right = mid;
                }
                /* Now left points to first element that is >= input_level, we need a previous element */
                const int index = (left > 0) ? left - 1 : 0;
                /* Piece-wise linear interploation. */
                const float gain = approximation_params_m[index] * input_level + approximation_params_q[index];
                temp_result[j] = gain;
            }
        }

        result_mid = _mm256_loadu_ps(temp_result);

        /* Combine results using masks */
        __m256 result = _mm256_blendv_ps(
            _mm256_blendv_ps(result_mid, result_high, mask_high),
            result_low,
            mask_low
        );

        /* Store results */
        _mm256_storeu_ps(&scaling_factors[i + 1], result);
    }

    /* Process remaining elements with scalar code */
    for (; i < K_SUB_FRAMES_IN_FRAME; ++i) {
        const float input_level = envelope[i];
        if (input_level <= approximation_params_x[0]) {
            /* Identity region. */
            scaling_factors[i+1] = 1.0f;
        } else if (input_level >= K_MAX_INPUT_LEVEL_LINEAR) {
            /* Saturating lower bound. The saturing samples exactly hit the clipping level.
             * This method achieves has the lowest harmonic distorsion, but it
             * may reduce the amplitude of the non-saturating samples too much.
             */
            scaling_factors[i+1] = 32768.f / input_level;
        } else {
            /* Knee and limiter regions; find the linear piece index. Searching in [0, K_INTERPOLATED_GAIN_CURVE_TOTAL_POINTS) */
            int left = 0;
            int right = K_INTERPOLATED_GAIN_CURVE_TOTAL_POINTS;
            while (left < right) {
                int mid = left + (right - left) / 2;
                if (approximation_params_x[mid] < input_level)
                    left = mid + 1;
                else
                    right = mid;
            }
            /* Now left points to first element that is >= input_level, we need a previous element */
            const int index = (left > 0) ? left - 1 : 0;
            /* Piece-wise linear interploation. */
            const float gain = approximation_params_m[index] * input_level + approximation_params_q[index];
            scaling_factors[i+1] = gain;
        }
    }

    *last_scaling_factor = scaling_factors[K_SUB_FRAMES_IN_FRAME];
}

static void compute_per_sample_scaling_factors_avx2(
    float scaling_factors[K_SUB_FRAMES_IN_FRAME + 1],
    float *per_sample_scaling_factors,
    int samples_in_sub_frame) {
    const int is_attack = scaling_factors[0] > scaling_factors[1];

    /* Handle attack section with scalar code (powf is difficult to vectorize efficiently) */
    if (is_attack) {
        for (int i = 0; i < samples_in_sub_frame; ++i) {
            float t = (float)i / samples_in_sub_frame;
            per_sample_scaling_factors[i] = powf(1.0f - t, K_ATTACK_FIRST_SUB_FRAME_INTERPOLATION_POWER) * (scaling_factors[0] - scaling_factors[1]) + scaling_factors[1];
        }
    }

    /* Vectorized linear interpolation for the main loop */
    for (int i = is_attack ? 1 : 0; i < K_SUB_FRAMES_IN_FRAME; ++i) {
        const int subframe_start = i * samples_in_sub_frame;
        const float scaling_start = scaling_factors[i];
        const float scaling_end = scaling_factors[i + 1];
        const float scaling_diff = (scaling_end - scaling_start) / samples_in_sub_frame;

        /* Vectorized processing - process 8 floats at a time */
        int j = 0;
        const __m256 v_scaling_start = _mm256_set1_ps(scaling_start);
        const __m256 v_scaling_diff = _mm256_set1_ps(scaling_diff);

        /* Process 8 elements at a time */
        for (; j + 8 <= samples_in_sub_frame; j += 8) {
            /* Create vector of indices [j, j+1, j+2, ..., j+7] */
            __m256i v_indices = _mm256_set_epi32(j+7, j+6, j+5, j+4, j+3, j+2, j+1, j);
            __m256 v_indices_f = _mm256_cvtepi32_ps(v_indices);

            /* Calculate scaling_start + scaling_diff * j for all 8 elements */
            __m256 v_result = _mm256_fmadd_ps(v_scaling_diff, v_indices_f, v_scaling_start);

            /* Store results */
            _mm256_storeu_ps(&per_sample_scaling_factors[subframe_start + j], v_result);
        }

        /* Handle remaining elements with scalar code */
        for (; j < samples_in_sub_frame; ++j) {
            per_sample_scaling_factors[subframe_start + j] = scaling_start + scaling_diff * j;
        }
    }
}

static void scale_buffer_avx2(
    opus_int32 *buffer,
    int samples,
    float *per_sample_scaling_factors,
    opus_int16 *outBuffer){

    int i = 0;
    /* Process 8 elements at a time */
    for (; i + 8 <= samples; i += 8) {
        /* Load 8 integers from buffer and convert to floats */
        __m256i v_int_vals = _mm256_loadu_si256((__m256i*)&buffer[i]);
        __m256 v_buf_vals = _mm256_cvtepi32_ps(v_int_vals);
        /* Load 8 scaling factors */
        __m256 v_scale_vals = _mm256_loadu_ps(&per_sample_scaling_factors[i]);
        /* Multiply buffer values with scaling factors */
        __m256 v_mult_result = _mm256_mul_ps(v_buf_vals, v_scale_vals);
        /* Convert to integers */
        __m256i v_int_result = _mm256_cvtps_epi32(v_mult_result);
        /* Pack 32-bit integers to 16-bit integers */
        /* First, pack the lower 4 32-bit values */
        __m128i v_low = _mm256_extracti128_si256(v_int_result, 0);
        __m128i v_high = _mm256_extracti128_si256(v_int_result, 1);
        __m128i v_packed = _mm_packs_epi32(v_low, v_high);
        /* Store the 8 16-bit integers */
        _mm_storeu_si128((__m128i*)&outBuffer[i], v_packed);
    }

    /* Handle remaining elements with scalar code */
    for (; i < samples; i++) {
        opus_int32 sample = (opus_int32)lrintf(buffer[i] * per_sample_scaling_factors[i]);
        if(sample > 32767)
            sample = 32767;
        else if(sample < -32768)
            sample = -32768;
        outBuffer[i] = sample;
    }
}
static void clamp_buffer_avx2(opus_int32 *buffer, int samples, opus_int16 *outBuffer){
    int i = 0;
    /* Process 8 elements at a time */
    for (; i + 8 <= samples; i += 8) {
        /* Load 8 integers from buffer */
        __m256i v_int_vals = _mm256_loadu_si256((__m256i*)&buffer[i]);
        /* Pack 32-bit integers to 16-bit integers */
        /* First, pack the lower 4 32-bit values */
        __m128i v_low = _mm256_extracti128_si256(v_int_vals, 0);
        __m128i v_high = _mm256_extracti128_si256(v_int_vals, 1);
        __m128i v_packed = _mm_packs_epi32(v_low, v_high);
        /* Store the 8 16-bit integers */
        _mm_storeu_si128((__m128i*)&outBuffer[i], v_packed);
    }

    /* Handle remaining elements with scalar code */
    for (; i < samples; i++) {
        opus_int32 sample = buffer[i];
        if(sample > 32767)
            sample = 32767;
        else if(sample < -32768)
            sample = -32768;
        outBuffer[i] = (opus_int16)sample;
    }
}
#endif
#if defined(__SSE4_2__)
static void scale_buffer_sse42(
    opus_int32 *buffer,
    int samples,
    float *per_sample_scaling_factors,
    opus_int16 *outBuffer){
    int i = 0;
    const __m128i v_zero = _mm_setzero_si128();
    /* Process 4 elements at a time */
    for (; i + 4 <= samples; i += 4) {
        /* Load 4 integers from buffer and convert to floats */
        __m128i v_int_vals = _mm_loadu_si128((__m128i*)&buffer[i]);
        __m128 v_buf_vals = _mm_cvtepi32_ps(v_int_vals);
        /* Load 4 scaling factors */
        __m128 v_scale_vals = _mm_loadu_ps(&per_sample_scaling_factors[i]);
        /* Multiply buffer values with scaling factors */
        __m128 v_mult_result = _mm_mul_ps(v_buf_vals, v_scale_vals);
        /* Convert to integers (truncation) */
        __m128i v_int_result = _mm_cvtps_epi32(v_mult_result);
        /* Pack 32-bit integers to 16-bit integers with saturation */
        __m128i v_packed = _mm_packs_epi32(v_int_result, v_zero);
        /* Store the 4 16-bit integers */
        _mm_storel_epi64((__m128i*)&outBuffer[i], v_packed);
    }

    /* Handle remaining elements with scalar code */
    for (; i < samples; i++) {
        opus_int32 sample = (opus_int32)lrintf(buffer[i] * per_sample_scaling_factors[i]);
        if(sample > 32767)
            sample = 32767;
        else if(sample < -32768)
            sample = -32768;
        outBuffer[i] = sample;
    }
}

static void compute_per_sample_scaling_factors_sse42(
    float scaling_factors[K_SUB_FRAMES_IN_FRAME + 1],
    float *per_sample_scaling_factors,
    int samples_in_sub_frame) {

    const int is_attack = scaling_factors[0] > scaling_factors[1];

    /* Handle attack section with scalar code (powf is difficult to vectorize efficiently) */
    if (is_attack) {
        for (int i = 0; i < samples_in_sub_frame; ++i) {
            float t = (float)i / samples_in_sub_frame;
            per_sample_scaling_factors[i] = powf(1.0f - t, K_ATTACK_FIRST_SUB_FRAME_INTERPOLATION_POWER) * (scaling_factors[0] - scaling_factors[1]) + scaling_factors[1];
        }
    }

    /* Vectorized linear interpolation for the main loop */
    for (int i = is_attack ? 1 : 0; i < K_SUB_FRAMES_IN_FRAME; ++i) {
        const int subframe_start = i * samples_in_sub_frame;
        const float scaling_start = scaling_factors[i];
        const float scaling_end = scaling_factors[i + 1];
        const float scaling_diff = (scaling_end - scaling_start) / samples_in_sub_frame;

        /* Vectorized processing - process 4 floats at a time */
        int j = 0;
        const __m128 v_scaling_start = _mm_set1_ps(scaling_start);
        const __m128 v_scaling_diff = _mm_set1_ps(scaling_diff);

        /* Process 4 elements at a time */
        for (; j + 4 <= samples_in_sub_frame; j += 4) {
            /* Create vector of indices [j, j+1, j+2, j+3] */
            __m128i v_indices = _mm_set_epi32(j+3, j+2, j+1, j);
            __m128 v_indices_f = _mm_cvtepi32_ps(v_indices);

            /* Calculate scaling_start + scaling_diff * j for all 4 elements */
            __m128 v_result = _mm_add_ps(v_scaling_start, _mm_mul_ps(v_scaling_diff, v_indices_f));

            /* Store results */
            _mm_storeu_ps(&per_sample_scaling_factors[subframe_start + j], v_result);
        }

        /* Handle remaining elements with scalar code */
        for (; j < samples_in_sub_frame; ++j) {
            per_sample_scaling_factors[subframe_start + j] = scaling_start + scaling_diff * j;
        }
    }
}
static void compute_max_envelope_sse42(opus_int32 *buffer, float envelope[K_SUB_FRAMES_IN_FRAME], int samples_in_sub_frame){
   /* Compute max envelope without smoothing. */
   int sub_frame, sample_in_sub_frame;
    /* SSE4.2 implementation - process 4 floats at a time */
    for (sub_frame = 0; sub_frame < K_SUB_FRAMES_IN_FRAME; ++sub_frame) {
        const opus_int32 *sub_frame_buffer = &buffer[sub_frame * samples_in_sub_frame];
        __m128 max_val = _mm_setzero_ps();

        /* Process 4 floats at a time */
        int simd_samples = (samples_in_sub_frame / 4) * 4;
        for (sample_in_sub_frame = 0; sample_in_sub_frame < simd_samples; sample_in_sub_frame += 4) {
            /* Load 4 integers and convert to floats */
            __m128i vals_i = _mm_loadu_si128((__m128i*)&sub_frame_buffer[sample_in_sub_frame]);
            __m128 vals = _mm_cvtepi32_ps(vals_i);

            /* Take absolute values */
            __m128 abs_vals = _mm_andnot_ps(_mm_set1_ps(-0.0f), vals);  /* Clear sign bit */

            max_val = _mm_max_ps(max_val, abs_vals);
        }

        /* Extract maximum from the vector */
        __m128 max_2 = _mm_max_ps(max_val, _mm_shuffle_ps(max_val, max_val, _MM_SHUFFLE(1, 0, 3, 2)));
        __m128 max_1 = _mm_max_ss(max_2, _mm_shuffle_ps(max_2, max_2, _MM_SHUFFLE(0, 0, 0, 1)));

        float max_scalar = _mm_cvtss_f32(max_1);

        /* Process remaining samples */
        for (; sample_in_sub_frame < samples_in_sub_frame; ++sample_in_sub_frame) {
            float abs_val = (float)abs(sub_frame_buffer[sample_in_sub_frame]);
            if (abs_val > max_scalar) {
                max_scalar = abs_val;
            }
        }

        if (max_scalar > envelope[sub_frame]) {
            envelope[sub_frame] = max_scalar;
        }
    }
}
static void calculate_scaling_factors_sse42(
    float envelope[K_SUB_FRAMES_IN_FRAME],
    float scaling_factors[K_SUB_FRAMES_IN_FRAME + 1],
    float *last_scaling_factor) {
    unsigned i;
    scaling_factors[0] = *last_scaling_factor;

    /* Constants for vectorized operations */
    const __m128 ones = _mm_set1_ps(1.0f);
    const __m128 threshold_low = _mm_set1_ps(approximation_params_x[0]);
    const __m128 threshold_high = _mm_set1_ps(K_MAX_INPUT_LEVEL_LINEAR);
    const __m128 scale_factor = _mm_set1_ps(32768.0f);

    /* Process 4 elements at a time */
    for (i = 0; i + 4 <= K_SUB_FRAMES_IN_FRAME; i += 4) {
        /* Load 4 input levels */
        __m128 input_levels = _mm_loadu_ps(&envelope[i]);

        /* Create masks for the three conditions */
        __m128 mask_low = _mm_cmp_ps(input_levels, threshold_low, _CMP_LE_OQ);
        __m128 mask_high = _mm_cmp_ps(input_levels, threshold_high, _CMP_GE_OQ);
        __m128 mask_mid = _mm_andnot_ps(mask_low, _mm_andnot_ps(mask_high, ones));

        /* Calculate scaling factors for each case */
        /* Case 1: input_level <= approximation_params_x[0] -> scaling factor = 1.0f */
        __m128 result_low = ones;

        /* Case 2: input_level >= K_MAX_INPUT_LEVEL_LINEAR -> scaling factor = 32768.f / input_level */
        __m128 result_high = _mm_div_ps(scale_factor, input_levels);

        /* Case 3: Middle region - use scalar processing for binary search */
        __m128 result_mid = _mm_setzero_ps();

        /* Handle middle region with scalar code (binary search cannot be easily vectorized) */
        float temp_input[4];
        float temp_result[4];
        _mm_storeu_ps(temp_input, input_levels);
        _mm_storeu_ps(temp_result, result_mid);

        for (int j = 0; j < 4; j++) {
            if (((float*)&mask_mid)[j] != 0.0f) {  /* Check if mask is set for this element */
                const float input_level = temp_input[j];
                /* Knee and limiter regions; find the linear piece index. Searching in [0, K_INTERPOLATED_GAIN_CURVE_TOTAL_POINTS) */
                int left = 0;
                int right = K_INTERPOLATED_GAIN_CURVE_TOTAL_POINTS;
                while (left < right) {
                    int mid = left + (right - left) / 2;
                    if (approximation_params_x[mid] < input_level)
                        left = mid + 1;
                    else
                        right = mid;
                }
                /* Now left points to first element that is >= input_level, we need a previous element */
                const int index = (left > 0) ? left - 1 : 0;
                /* Piece-wise linear interploation. */
                const float gain = approximation_params_m[index] * input_level + approximation_params_q[index];
                temp_result[j] = gain;
            }
        }

        result_mid = _mm_loadu_ps(temp_result);

        /* Combine results using masks */
        __m128 result = _mm_blendv_ps(
            _mm_blendv_ps(result_mid, result_high, mask_high),
            result_low,
            mask_low
        );

        /* Store results */
        _mm_storeu_ps(&scaling_factors[i + 1], result);
    }

    /* Process remaining elements with scalar code */
    for (; i < K_SUB_FRAMES_IN_FRAME; ++i) {
        const float input_level = envelope[i];
        if (input_level <= approximation_params_x[0]) {
            /* Identity region. */
            scaling_factors[i+1] = 1.0f;
        } else if (input_level >= K_MAX_INPUT_LEVEL_LINEAR) {
            /* Saturating lower bound. The saturing samples exactly hit the clipping level.
             * This method achieves has the lowest harmonic distorsion, but it
             * may reduce the amplitude of the non-saturating samples too much.
             */
            scaling_factors[i+1] = 32768.f / input_level;
        } else {
            /* Knee and limiter regions; find the linear piece index. Searching in [0, K_INTERPOLATED_GAIN_CURVE_TOTAL_POINTS) */
            int left = 0;
            int right = K_INTERPOLATED_GAIN_CURVE_TOTAL_POINTS;
            while (left < right) {
                int mid = left + (right - left) / 2;
                if (approximation_params_x[mid] < input_level)
                    left = mid + 1;
                else
                    right = mid;
            }
            /* Now left points to first element that is >= input_level, we need a previous element */
            const int index = (left > 0) ? left - 1 : 0;
            /* Piece-wise linear interploation. */
            const float gain = approximation_params_m[index] * input_level + approximation_params_q[index];
            scaling_factors[i+1] = gain;
        }
    }

    *last_scaling_factor = scaling_factors[K_SUB_FRAMES_IN_FRAME];
}

static void clamp_buffer_sse42(opus_int32 *buffer, int samples, opus_int16 *outBuffer){
    int i = 0;
    /* Process 4 elements at a time */
    for (; i + 4 <= samples; i += 4) {
        /* Load 4 integers from buffer */
        __m128i vec_int32 = _mm_loadu_si128((__m128i*)&buffer[i]);
        /* Pack 32-bit integers to 16-bit integers with saturation */
        __m128i vec_int16_packed = _mm_packs_epi32(vec_int32, _mm_setzero_si128());
        /* Store the 4 16-bit integers */
        _mm_storel_epi64((__m128i*)&outBuffer[i], vec_int16_packed);
    }

    /* Handle remaining elements with scalar code */
    for (; i < samples; i++) {
        opus_int32 sample = buffer[i];
        if(sample > 32767)
            sample = 32767;
        else if(sample < -32768)
            sample = -32768;
        outBuffer[i] = (opus_int16)sample;
    }
}
#endif

static void compute_max_envelope_scalar(opus_int32 *buffer, float envelope[K_SUB_FRAMES_IN_FRAME], int samples_in_sub_frame){
   /* Compute max envelope without smoothing. */
   int sub_frame, sample_in_sub_frame;
    for (sub_frame = 0; sub_frame < K_SUB_FRAMES_IN_FRAME; ++sub_frame) {
        for (sample_in_sub_frame = 0; sample_in_sub_frame < samples_in_sub_frame; ++sample_in_sub_frame) {
            envelope[sub_frame] = fmax(envelope[sub_frame], abs(buffer[sub_frame * samples_in_sub_frame + sample_in_sub_frame]));
        }
    }
}

static inline __attribute__((always_inline)) void compute_envelope(
    opus_int32 *buffer,
    float envelope[K_SUB_FRAMES_IN_FRAME],
    int samples_in_sub_frame,
    float *filter_state_level) {
    int sub_frame;
    compute_max_envelope_func(buffer, envelope, samples_in_sub_frame);

    /* Make sure envelope increases happen one step earlier so that the
     * corresponding *gain decrease* doesn't miss a sudden signal
     *  increase due to interpolation.
     */
    for (sub_frame = 0; sub_frame < K_SUB_FRAMES_IN_FRAME - 1; ++sub_frame) {
        if (envelope[sub_frame] < envelope[sub_frame + 1])
            envelope[sub_frame] = envelope[sub_frame + 1];
    }

    /* Add attack / decay smoothing. */
    for (sub_frame = 0; sub_frame < K_SUB_FRAMES_IN_FRAME; ++sub_frame) {
        const float envelope_value = envelope[sub_frame];
        if (envelope_value > *filter_state_level) {
            envelope[sub_frame] = envelope_value * (1 - K_ATTACK_FILTER_CONSTANT) + *filter_state_level * K_ATTACK_FILTER_CONSTANT;
        } else {
            envelope[sub_frame] = envelope_value * (1 - K_DECAY_FILTER_CONSTANT) + *filter_state_level * K_DECAY_FILTER_CONSTANT;
        }
        *filter_state_level = envelope[sub_frame];
    }
}
static void compute_per_sample_scaling_factors_scalar(
    float scaling_factors[K_SUB_FRAMES_IN_FRAME + 1],
    float *per_sample_scaling_factors,
    int samples_in_sub_frame) {

    const int is_attack = scaling_factors[0] > scaling_factors[1];
    if (is_attack) {
        for (int i = 0; i < samples_in_sub_frame; ++i) {
            float t = (float)i / samples_in_sub_frame;
            per_sample_scaling_factors[i] = powf(1.0f - t, K_ATTACK_FIRST_SUB_FRAME_INTERPOLATION_POWER) * (scaling_factors[0] - scaling_factors[1]) + scaling_factors[1];
        }
    }

    for (int i = is_attack ? 1 : 0; i < K_SUB_FRAMES_IN_FRAME; ++i) {
        const int subframe_start = i * samples_in_sub_frame;
        const float scaling_start = scaling_factors[i];
        const float scaling_end = scaling_factors[i + 1];
        const float scaling_diff = (scaling_end - scaling_start) / samples_in_sub_frame;

        for (int j = 0; j < samples_in_sub_frame; ++j) {
            per_sample_scaling_factors[subframe_start + j] = scaling_start + scaling_diff * j;
        }
    }
}

static void calculate_scaling_factors_scalar(
    float envelope[K_SUB_FRAMES_IN_FRAME],
    float scaling_factors[K_SUB_FRAMES_IN_FRAME + 1],
    float *last_scaling_factor) {

    int i;

    scaling_factors[0] = *last_scaling_factor;
    for (i = 0; i < K_SUB_FRAMES_IN_FRAME; ++i) {
        const float input_level = envelope[i];
        if (input_level <= approximation_params_x[0]) {
            /* Identity region. */
            scaling_factors[i+1] = 1.0f;
        } else if (input_level >= K_MAX_INPUT_LEVEL_LINEAR) {
            /* Saturating lower bound. The saturing samples exactly hit the clipping level.
             * This method achieves has the lowest harmonic distorsion, but it
             * may reduce the amplitude of the non-saturating samples too much.
             */
            scaling_factors[i+1] = 32768.f / input_level;
        } else {
            /* Knee and limiter regions; find the linear piece index. Searching in [0, K_INTERPOLATED_GAIN_CURVE_TOTAL_POINTS) */
            int left = 0;
            int right = K_INTERPOLATED_GAIN_CURVE_TOTAL_POINTS;
            while (left < right) {
                int mid = left + (right - left) / 2;
                if (approximation_params_x[mid] < input_level)
                    left = mid + 1;
                else
                    right = mid;
            }
            /* Now left points to first element that is >= input_level, we need a previous element */
            const int index = (left > 0) ? left - 1 : 0;
            /* Piece-wise linear interploation. */
            const float gain = approximation_params_m[index] * input_level + approximation_params_q[index];
            scaling_factors[i+1] = gain;
        }
    }

    *last_scaling_factor = scaling_factors[K_SUB_FRAMES_IN_FRAME];
}

inline __attribute__((always_inline)) void compute_scaling_factors(
	opus_int32 *buffer,
	float envelope[K_SUB_FRAMES_IN_FRAME],
	float scaling_factors[K_SUB_FRAMES_IN_FRAME + 1],
	float *per_sample_scaling_factors,
	int samples_in_sub_frame,
	float *filter_state_level,
	float *last_scaling_factor) {
	/*
	 * Calculating gain factors for limiter (adapted from WebRTC project).
	 * Original WebRTC code: https://webrtc.googlesource.com/src
	 * Licensed under BSD 3-Clause License.
	 */
	compute_envelope(buffer, envelope, samples_in_sub_frame, filter_state_level);
	calculate_scaling_factors_func(envelope, scaling_factors, last_scaling_factor);
	compute_per_sample_scaling_factors_func(scaling_factors, per_sample_scaling_factors, samples_in_sub_frame);
}

static void scale_buffer_scalar(
    opus_int32 *buffer,
    int samples,
    float *per_sample_scaling_factors,
    opus_int16 *outBuffer){
    int i;
    opus_int32 sample;
    for(i=0; i<samples; i++) {
        sample = (opus_int32)lrintf(buffer[i] * per_sample_scaling_factors[i]);
        if(sample > 32767)
            sample = 32767;
        else if(sample < -32768)
            sample = -32768;
        outBuffer[i] = sample;
    }
}

inline __attribute__((always_inline)) void scale_buffer(
    opus_int32 *buffer,
    int samples,
    float *per_sample_scaling_factors,
    opus_int16 *outBuffer){
    scale_buffer_func(buffer, samples, per_sample_scaling_factors, outBuffer);
}


static void clamp_buffer_scalar(opus_int32 *buffer, int samples, opus_int16 *outBuffer){
    int i;
    opus_int32 sample;
    for(i=0; i<samples; i++) {
        sample = buffer[i];
        if(sample > 32767)
            sample = 32767;
        else if(sample < -32768)
            sample = -32768;
        outBuffer[i] = (opus_int16)sample;
    }
}

inline __attribute__((always_inline)) void clamp_buffer(opus_int32 *buffer, int samples, opus_int16 *outBuffer){
    clamp_buffer_func(buffer, samples, outBuffer);
}

#if defined(__AVX2__)
inline __attribute__((always_inline)) void init_limiter_avx2(void) {
    JANUS_LOG(LOG_INFO, "Using AVX2 implementation of limiter\n");
    compute_max_envelope_func = compute_max_envelope_avx2;
    calculate_scaling_factors_func = calculate_scaling_factors_avx2;
    compute_per_sample_scaling_factors_func = compute_per_sample_scaling_factors_avx2;
    scale_buffer_func = scale_buffer_avx2;
    clamp_buffer_func = clamp_buffer_avx2;
}
#endif

#if defined(__SSE4_2__)
inline __attribute__((always_inline)) void init_limiter_sse42(void) {
    JANUS_LOG(LOG_INFO, "Using SSE4.2 implementation of limiter\n");
        compute_max_envelope_func = compute_max_envelope_sse42;
        calculate_scaling_factors_func = calculate_scaling_factors_sse42;
        compute_per_sample_scaling_factors_func = compute_per_sample_scaling_factors_sse42;
        scale_buffer_func = scale_buffer_sse42;
        clamp_buffer_func = clamp_buffer_sse42;
}
#endif

inline __attribute__((always_inline)) void init_limiter_scalar(void) {
    JANUS_LOG(LOG_INFO, "Using scalar implementation of limiter\n");
    compute_max_envelope_func = compute_max_envelope_scalar;
    calculate_scaling_factors_func = calculate_scaling_factors_scalar;
    compute_per_sample_scaling_factors_func = compute_per_sample_scaling_factors_scalar;
    scale_buffer_func = scale_buffer_scalar;
    clamp_buffer_func = clamp_buffer_scalar;
}

inline __attribute__((always_inline)) void init_limiter(void) {
    #if defined(__AVX2__)
    if (has_avx2()) {
        init_limiter_avx2();
        return;
    }
    #endif
    #if defined(__SSE4_2__)
    if (has_sse42()) {
        init_limiter_sse42();
        return;
    }
    #endif
    init_limiter_scalar();
}
