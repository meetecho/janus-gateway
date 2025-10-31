#include <opus/opus.h>
#include <sys/time.h>
#include <poll.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <glib.h>
#include <limits.h>
#include <stdio.h>
#include <math.h>
#include "limiter.h"

#define	OPUS_SAMPLES	960
#define SAMPLING_RATE 48000
#define TEST_ITERATIONS 100000

int main(void) {
	int samples = SAMPLING_RATE/50;
	opus_int32 buffer[OPUS_SAMPLES];
	opus_int16 outBuffer_scalar[OPUS_SAMPLES],
	outBuffer_avx2[OPUS_SAMPLES],
	outBuffer_sse42[OPUS_SAMPLES];
	memset(buffer, 0, OPUS_SAMPLES*(4));
	memset(outBuffer_scalar, 0, OPUS_SAMPLES*(2));
	memset(outBuffer_avx2, 0, OPUS_SAMPLES*(2));
	memset(outBuffer_sse42, 0, OPUS_SAMPLES*(2));
	int i=0, t=0;

	/* For audio limiter we split frame in subframes */
	int samples_in_sub_frame = samples / K_SUB_FRAMES_IN_FRAME;
	
	/* scalar */
	float *per_sample_scaling_factors_scalar = g_malloc0(OPUS_SAMPLES * sizeof(float));
	float *envelope_scalar = g_malloc0(K_SUB_FRAMES_IN_FRAME * sizeof(float));
	float *scaling_factors_scalar = g_malloc0((K_SUB_FRAMES_IN_FRAME + 1) * sizeof(float));

	/* avx2 */
	float *per_sample_scaling_factors_avx2 = g_malloc0(OPUS_SAMPLES * sizeof(float));
	float *envelope_avx2 = g_malloc0(K_SUB_FRAMES_IN_FRAME * sizeof(float));
	float *scaling_factors_avx2 = g_malloc0((K_SUB_FRAMES_IN_FRAME + 1) * sizeof(float));

	/* sse42 */
	float *per_sample_scaling_factors_sse42 = g_malloc0(OPUS_SAMPLES * sizeof(float));
	float *envelope_sse42 = g_malloc0(K_SUB_FRAMES_IN_FRAME * sizeof(float));
	float *scaling_factors_sse42 = g_malloc0((K_SUB_FRAMES_IN_FRAME + 1) * sizeof(float));


	for (t=0; t<TEST_ITERATIONS; t++) {
		/* Arrange */
		float last_scaling_factor_scalar = 1.f;
		float filter_state_level_scalar = K_INITIAL_FILTER_STATE_LEVEL;
		float last_scaling_factor_avx2 = 1.f;
		float filter_state_level_avx2 = K_INITIAL_FILTER_STATE_LEVEL;
		float last_scaling_factor_sse42 = 1.f;
		float filter_state_level_sse42 = K_INITIAL_FILTER_STATE_LEVEL;
		for (i=0; i<samples; i++) {
			buffer[i] = (opus_int32)(((uint32_t)rand() << 16) | rand());
		}

		/* Act */
		init_limiter_scalar();
		compute_scaling_factors(buffer, envelope_scalar, scaling_factors_scalar, per_sample_scaling_factors_scalar,
			samples_in_sub_frame, &filter_state_level_scalar, &last_scaling_factor_scalar);
		scale_buffer(buffer, samples, per_sample_scaling_factors_scalar, outBuffer_scalar);

		init_limiter_avx2();
		compute_scaling_factors(buffer, envelope_avx2, scaling_factors_avx2, per_sample_scaling_factors_avx2,
			samples_in_sub_frame, &filter_state_level_avx2, &last_scaling_factor_avx2);
		scale_buffer(buffer, samples, per_sample_scaling_factors_avx2, outBuffer_avx2);

		init_limiter_sse42();
		compute_scaling_factors(buffer, envelope_sse42, scaling_factors_sse42, per_sample_scaling_factors_sse42,
			samples_in_sub_frame, &filter_state_level_sse42, &last_scaling_factor_sse42);
		scale_buffer(buffer, samples, per_sample_scaling_factors_sse42, outBuffer_sse42);

		/* Assert */
		for (i=0; i<K_SUB_FRAMES_IN_FRAME; i++) {
			if (envelope_scalar[i] != envelope_avx2[i] || envelope_scalar[i] != envelope_sse42[i]) {
				printf("Error(envelope): scalar(%f) avx2(%f) sse42(%f) at index %d\n", envelope_scalar[i], envelope_avx2[i], envelope_sse42[i], i);
				return 1;
			}
		}
		for (i=0; i<K_SUB_FRAMES_IN_FRAME+1; i++) {
			if (scaling_factors_scalar[i] != scaling_factors_avx2[i] || scaling_factors_scalar[i] != scaling_factors_sse42[i]) {
				printf("Error(scaling_factors): scalar(%f) avx2(%f) sse42(%f) at index %d\n", scaling_factors_scalar[i], scaling_factors_avx2[i], scaling_factors_sse42[i], i);
				return 1;
			}
			if (i == 0) {
				/* First scaling factor is always 1 */
				if (scaling_factors_scalar[i] != 1.f) {
					printf("Error(scaling_factors wrong value): scalar(%f) avx2(%f) sse42(%f) at index %d\n",
						scaling_factors_scalar[i], scaling_factors_avx2[i], scaling_factors_sse42[i], i);
					return 1;
				}
			} else {
				/* Large values must be scaled close to int16 boundaries */
				opus_int32 scaled = (opus_int32)(scaling_factors_scalar[i] * buffer[i]);
				if ((buffer[i] < SHRT_MIN || buffer[i] > SHRT_MAX)
					&& (scaled > SHRT_MAX || scaled < SHRT_MIN)
					&& abs(scaled - outBuffer_scalar[i]) > 1) {
					printf("Error(scaling_factors wrong value): scalar(%f) avx2(%f) sse42(%f) at index %d\n",
						scaling_factors_scalar[i], scaling_factors_avx2[i], scaling_factors_sse42[i], i);
					printf("Buffer: %d Scaled: %d\n", buffer[i], scaled);
					printf("Iteration %d\n", t);
					return 1;
				}
			}
		}
		for (i=0; i<samples; i++) {
			if (outBuffer_scalar[i] != outBuffer_avx2[i] || outBuffer_scalar[i] != outBuffer_sse42[i]) {
				printf("Error(outBuffer): scalar(%d) avx2(%d) sse42(%d) at index %d\n", outBuffer_scalar[i], outBuffer_avx2[i], outBuffer_sse42[i], i);
				return 1;
			}
		}
	}
	printf("Limiter works fine (scalar, sse4.2 and avx2)\n");
	return 0;
}