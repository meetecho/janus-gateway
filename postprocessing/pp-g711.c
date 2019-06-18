/*! \file    pp-g711.c
 * \author   Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief    Post-processing to generate .wav files (headers)
 * \details  Implementation of the post-processing code needed to
 * generate raw .wav files out of G.711 (mu-law or a-law) RTP frames.
 *
 * \ingroup postprocessing
 * \ref postprocessing
 */

#include <arpa/inet.h>
#ifdef __MACH__
#include <machine/endian.h>
#else
#include <endian.h>
#endif
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

#include "pp-g711.h"
#include "../debug.h"


/* WAV header */
typedef struct janus_pp_g711_wav {
	char riff[4];
	uint32_t len;
	char wave[4];
	char fmt[4];
	uint32_t formatsize;
	uint16_t format;
	uint16_t channels;
	uint32_t samplerate;
	uint32_t avgbyterate;
	uint16_t samplebytes;
	uint16_t channelbits;
	char data[4];
	uint32_t blocksize;
} janus_pp_g711_wav;
static FILE *wav_file = NULL;


/* mu-law decoding table */
int16_t janus_pp_g711_mulaw_table[256] =
{
     -32124,-31100,-30076,-29052,-28028,-27004,-25980,-24956,
     -23932,-22908,-21884,-20860,-19836,-18812,-17788,-16764,
     -15996,-15484,-14972,-14460,-13948,-13436,-12924,-12412,
     -11900,-11388,-10876,-10364, -9852, -9340, -8828, -8316,
      -7932, -7676, -7420, -7164, -6908, -6652, -6396, -6140,
      -5884, -5628, -5372, -5116, -4860, -4604, -4348, -4092,
      -3900, -3772, -3644, -3516, -3388, -3260, -3132, -3004,
      -2876, -2748, -2620, -2492, -2364, -2236, -2108, -1980,
      -1884, -1820, -1756, -1692, -1628, -1564, -1500, -1436,
      -1372, -1308, -1244, -1180, -1116, -1052,  -988,  -924,
       -876,  -844,  -812,  -780,  -748,  -716,  -684,  -652,
       -620,  -588,  -556,  -524,  -492,  -460,  -428,  -396,
       -372,  -356,  -340,  -324,  -308,  -292,  -276,  -260,
       -244,  -228,  -212,  -196,  -180,  -164,  -148,  -132,
       -120,  -112,  -104,   -96,   -88,   -80,   -72,   -64,
        -56,   -48,   -40,   -32,   -24,   -16,    -8,     0,
      32124, 31100, 30076, 29052, 28028, 27004, 25980, 24956,
      23932, 22908, 21884, 20860, 19836, 18812, 17788, 16764,
      15996, 15484, 14972, 14460, 13948, 13436, 12924, 12412,
      11900, 11388, 10876, 10364,  9852,  9340,  8828,  8316,
       7932,  7676,  7420,  7164,  6908,  6652,  6396,  6140,
       5884,  5628,  5372,  5116,  4860,  4604,  4348,  4092,
       3900,  3772,  3644,  3516,  3388,  3260,  3132,  3004,
       2876,  2748,  2620,  2492,  2364,  2236,  2108,  1980,
       1884,  1820,  1756,  1692,  1628,  1564,  1500,  1436,
       1372,  1308,  1244,  1180,  1116,  1052,   988,   924,
        876,   844,   812,   780,   748,   716,   684,   652,
        620,   588,   556,   524,   492,   460,   428,   396,
        372,   356,   340,   324,   308,   292,   276,   260,
        244,   228,   212,   196,   180,   164,   148,   132,
        120,   112,   104,    96,    88,    80,    72,    64,
         56,    48,    40,    32,    24,    16,     8,     0
};

/* a-law decoding table */
int16_t janus_pp_g711_alaw_table[256] =
{
     -5504, -5248, -6016, -5760, -4480, -4224, -4992, -4736,
     -7552, -7296, -8064, -7808, -6528, -6272, -7040, -6784,
     -2752, -2624, -3008, -2880, -2240, -2112, -2496, -2368,
     -3776, -3648, -4032, -3904, -3264, -3136, -3520, -3392,
     -22016,-20992,-24064,-23040,-17920,-16896,-19968,-18944,
     -30208,-29184,-32256,-31232,-26112,-25088,-28160,-27136,
     -11008,-10496,-12032,-11520,-8960, -8448, -9984, -9472,
     -15104,-14592,-16128,-15616,-13056,-12544,-14080,-13568,
     -344,  -328,  -376,  -360,  -280,  -264,  -312,  -296,
     -472,  -456,  -504,  -488,  -408,  -392,  -440,  -424,
     -88,   -72,   -120,  -104,  -24,   -8,    -56,   -40,
     -216,  -200,  -248,  -232,  -152,  -136,  -184,  -168,
     -1376, -1312, -1504, -1440, -1120, -1056, -1248, -1184,
     -1888, -1824, -2016, -1952, -1632, -1568, -1760, -1696,
     -688,  -656,  -752,  -720,  -560,  -528,  -624,  -592,
     -944,  -912,  -1008, -976,  -816,  -784,  -880,  -848,
      5504,  5248,  6016,  5760,  4480,  4224,  4992,  4736,
      7552,  7296,  8064,  7808,  6528,  6272,  7040,  6784,
      2752,  2624,  3008,  2880,  2240,  2112,  2496,  2368,
      3776,  3648,  4032,  3904,  3264,  3136,  3520,  3392,
      22016, 20992, 24064, 23040, 17920, 16896, 19968, 18944,
      30208, 29184, 32256, 31232, 26112, 25088, 28160, 27136,
      11008, 10496, 12032, 11520, 8960,  8448,  9984,  9472,
      15104, 14592, 16128, 15616, 13056, 12544, 14080, 13568,
      344,   328,   376,   360,   280,   264,   312,   296,
      472,   456,   504,   488,   408,   392,   440,   424,
      88,    72,   120,   104,    24,     8,    56,    40,
      216,   200,   248,   232,   152,   136,   184,   168,
      1376,  1312,  1504,  1440,  1120,  1056,  1248,  1184,
      1888,  1824,  2016,  1952,  1632,  1568,  1760,  1696,
      688,   656,   752,   720,   560,   528,   624,   592,
      944,   912,  1008,   976,   816,   784,   880,   848
};


/* Processing methods */
int janus_pp_g711_create(char *destination, char *metadata) {
	/* Create wav file */
	wav_file = fopen(destination, "wb");
	if(wav_file == NULL) {
		JANUS_LOG(LOG_ERR, "Couldn't open output file\n");
		return -1;
	}
	/* Add header */
	JANUS_LOG(LOG_INFO, "Writing .wav file header\n");
	janus_pp_g711_wav header = {
		{'R', 'I', 'F', 'F'},
		0,
		{'W', 'A', 'V', 'E'},
		{'f', 'm', 't', ' '},
		16,
		1,
		1,
		8000,
		16000,
		2,
		16,
		{'d', 'a', 't', 'a'},
		0
	};
	/* Note: .wav files don't seem to support arbitrary comments
	 * so there's nothing we can do with the provided metadata*/
	if(fwrite(&header, 1, sizeof(header), wav_file) != sizeof(header)) {
		JANUS_LOG(LOG_ERR, "Couldn't write WAV header, expect problems...\n");
	}
	fflush(wav_file);
	return 0;
}

int janus_pp_g711_process(FILE *file, janus_pp_frame_packet *list, int *working) {
	if(!file || !list || !working)
		return -1;
	janus_pp_frame_packet *tmp = list;
	long int offset = 0;
	int bytes = 0, len = 0, steps = 0, last_seq = 0;
	uint8_t *buffer = g_malloc0(1500);
	int16_t samples[1500];
	memset(samples, 0, sizeof(samples));
	size_t num_samples = 160;
	while(*working && tmp != NULL) {
		if(tmp->prev != NULL && (tmp->seq - tmp->prev->seq > 1)) {
			JANUS_LOG(LOG_WARN, "Lost a packet here? (got seq %"SCNu16" after %"SCNu16", time ~%"SCNu64"s)\n",
				tmp->seq, tmp->prev->seq, (tmp->ts-list->ts)/48000);
			/* FIXME Write the silence packet N times to fill in the gaps */
			int i=0;
			for(i=0; i<(tmp->seq-tmp->prev->seq-1); i++) {
				/* FIXME We should actually also look at the timestamp differences */
				JANUS_LOG(LOG_WARN, "[FILL] Writing silence (seq=%d, index=%d)\n",
					tmp->prev->seq+i+1, i+1);
				/* Add silence */
				memset(samples, 0, num_samples*2);
				if(wav_file != NULL) {
					if(fwrite(samples, sizeof(uint16_t), num_samples, wav_file) != num_samples) {
						JANUS_LOG(LOG_ERR, "Couldn't write sample...\n");
					}
					fflush(wav_file);
				}
			}
		}
		if(tmp->drop) {
			/* We marked this packet as one to drop, before */
			JANUS_LOG(LOG_WARN, "Dropping previously marked audio packet (time ~%"SCNu64"s)\n", (tmp->ts-list->ts)/48000);
			tmp = tmp->next;
			continue;
		}
		if(tmp->audiolevel != -1) {
			JANUS_LOG(LOG_VERB, "Audio level: %d dB\n", tmp->audiolevel);
		}
		guint16 diff = tmp->prev == NULL ? 1 : (tmp->seq - tmp->prev->seq);
		len = 0;
		/* RTP payload */
		offset = tmp->offset+12+tmp->skip;
		fseek(file, offset, SEEK_SET);
		len = tmp->len-12-tmp->skip;
		if(len < 1) {
			tmp = tmp->next;
			continue;
		}
		bytes = fread(buffer, sizeof(char), len, file);
		if(bytes != len) {
			JANUS_LOG(LOG_WARN, "Didn't manage to read all the bytes we needed (%d < %d)...\n", bytes, len);
			tmp = tmp->next;
			continue;
		}
		if(last_seq == 0)
			last_seq = tmp->seq;
		if(tmp->seq < last_seq) {
			last_seq = tmp->seq;
			steps++;
		}
		JANUS_LOG(LOG_VERB, "Writing %d bytes out of %d (seq=%"SCNu16", step=%"SCNu16", ts=%"SCNu64", time=%"SCNu64"s)\n",
			bytes, tmp->len, tmp->seq, diff, tmp->ts, (tmp->ts-list->ts)/8000);
		/* Decode and save to wav */
		uint8_t *data = (uint8_t *)buffer;
		int i=0;
		if(tmp->pt == 0) {
			/* mu-law */
			for(i=0; i<bytes; i++)
				samples[i] = janus_pp_g711_mulaw_table[*data++];
		} else if(tmp->pt == 8) {
			/* a-law */
			for(i=0; i<bytes; i++)
				samples[i] = janus_pp_g711_alaw_table[*data++];
		} else {
			JANUS_LOG(LOG_WARN, "Skipping unsupported payload type %d\n", tmp->pt);
		}
		if(wav_file != NULL) {
			num_samples = bytes;
			if(fwrite(samples, sizeof(int16_t), bytes, wav_file) != num_samples) {
				JANUS_LOG(LOG_ERR, "Couldn't write sample...\n");
			}
			fflush(wav_file);
		}
		tmp = tmp->next;
	}
	g_free(buffer);
	return 0;
}

void janus_pp_g711_close(void) {
	/* Flush and close file */
	if(wav_file != NULL) {
		fflush(wav_file);
		fclose(wav_file);
	}
	wav_file = NULL;
}
