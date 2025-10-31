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
	for (t=0; t<TEST_ITERATIONS; t++) {
		/* Arrange */
		for (i=0; i<samples; i++) {
			buffer[i] = (opus_int32)(((uint32_t)rand() << 16) | rand());;
		}

		/* Act */
		init_limiter_scalar();
		clamp_buffer(buffer, samples, outBuffer_scalar);

		init_limiter_avx2();
		clamp_buffer(buffer, samples, outBuffer_avx2);

		init_limiter_sse42();
		clamp_buffer(buffer, samples, outBuffer_sse42);

		/* Assert */
		for (i=0; i<samples; i++) {
			if (outBuffer_scalar[i] != outBuffer_avx2[i] || outBuffer_scalar[i] != outBuffer_sse42[i]) {
				printf("Error(outBuffer): scalar(%d) avx2(%d) sse42(%d) at index %d\n", outBuffer_scalar[i], outBuffer_avx2[i], outBuffer_sse42[i], i);
				return 1;
			}
			if ((buffer[i] > SHRT_MAX && outBuffer_scalar[i] != SHRT_MAX)
				|| (buffer[i] < SHRT_MIN && outBuffer_scalar[i] != SHRT_MIN)) {
				printf("Error(outBuffer wrong value): scalar(%d) avx2(%d) sse42(%d) at index %d\n", outBuffer_scalar[i], outBuffer_avx2[i], outBuffer_sse42[i], i);
				return 1;
			}
		}
	}
	printf("Clamp works fine (scalar, sse4.2 and avx2)\n");
	return 0;
}