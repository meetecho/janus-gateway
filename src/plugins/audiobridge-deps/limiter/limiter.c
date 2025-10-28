#include "limiter.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../../debug.h"

/* SIMD intrinsics */
#if defined(__AVX2__) || defined(__SSE4_2__)
#include <immintrin.h>
#include <cpuid.h>

int has_avx2() {
    unsigned int eax, ebx, ecx, edx;
    // First check leaf 1
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        if ((ecx & bit_OSXSAVE) && (ecx & bit_AVX)) {
            if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
                return (ebx & (1 << 5)) != 0;  /* AVX2 — bit 5 of EBX */
            }
        }
    }
    return 0;
}
int has_sse42() {
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & (1 << 20)) != 0;  /* SSE4.2 — bit 20 of ECX */
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


/* Function pointer for the selected implementation */
static void (*compute_max_envelope_func)(opus_int32 *buffer, float *envelope, int samples_in_sub_frame) = NULL;

#if defined(__AVX2__)
void compute_max_envelope_avx2(opus_int32 *buffer, float *envelope, int samples_in_sub_frame){
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
#endif
#if defined(__SSE4_2__)
void compute_max_envelope_sse42(opus_int32 *buffer, float *envelope, int samples_in_sub_frame){
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
#endif


static void compute_max_envelope_scalar(opus_int32 *buffer, float *envelope, int samples_in_sub_frame){
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
    float *envelope,
    int samples_in_sub_frame,
    float *filter_state_level) {
    int sub_frame, sample_in_sub_frame;
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
static inline __attribute__((always_inline)) void compute_per_sample_scaling_factors(
    float *scaling_factors,
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

static inline __attribute__((always_inline)) void calculate_scaling_factors(
    float *envelope,
    float *scaling_factors,
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
            size_t left = 0;
            size_t right = K_INTERPOLATED_GAIN_CURVE_TOTAL_POINTS;
            while (left < right) {
                size_t mid = left + (right - left) / 2;
                if (approximation_params_x[mid] < input_level)
                    left = mid + 1;
                else
                    right = mid;
            }
            /* Now left points to first element that is >= input_level, we need a previous element */
            const size_t index = (left > 0) ? left - 1 : 0;
            /* Piece-wise linear interploation. */
            const float gain = approximation_params_m[index] * input_level + approximation_params_q[index];
            scaling_factors[i+1] = gain;
        }
    }
    
    *last_scaling_factor = scaling_factors[K_SUB_FRAMES_IN_FRAME];
}

inline __attribute__((always_inline)) void compute_scaling_factors(
	opus_int32 *buffer, 
	float *envelope, 
	float *scaling_factors, 
	float *per_sample_scaling_factors, 
	int samples_in_sub_frame, 
	float *filter_state_level, 
	float *last_scaling_factor) {
	
	int sub_frame, sample_in_sub_frame;
	
	/*
	 * Calculating gain factors for limiter (adapted from WebRTC project).
	 * Original WebRTC code: https://webrtc.googlesource.com/src
	 * Licensed under BSD 3-Clause License.
	 */
	compute_envelope(buffer, envelope, samples_in_sub_frame, filter_state_level);
	calculate_scaling_factors(envelope, scaling_factors, last_scaling_factor);
	compute_per_sample_scaling_factors(scaling_factors, per_sample_scaling_factors, samples_in_sub_frame);
}

inline __attribute__((always_inline)) void init_limiter() {
    #if defined(__AVX2__)
    if (has_avx2()) {
        JANUS_LOG(LOG_INFO, "Using AVX2 implementation of limiter\n");
        compute_max_envelope_func = compute_max_envelope_avx2;
        return;
    }
    #endif
    #if defined(__SSE4_2__)
    if (has_sse42()) {
        JANUS_LOG(LOG_INFO, "Using SSE4.2 implementation of limiter\n");
        compute_max_envelope_func = compute_max_envelope_sse42;
        return;
    } 
    #endif
 
    JANUS_LOG(LOG_INFO, "Using scalar implementation of limiter\n");
    compute_max_envelope_func = compute_max_envelope_scalar;
}