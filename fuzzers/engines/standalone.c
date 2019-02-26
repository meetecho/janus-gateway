#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

extern int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);

int main(int argc, char **argv) {
	for (int i = 1; i < argc; i++) {
		fprintf(stderr, "Running: %s\n", argv[i]);
		FILE *f = fopen(argv[i], "r");
		fseek(f, 0, SEEK_END);
		size_t len = ftell(f);
		fseek(f, 0, SEEK_SET);
		unsigned char *buf = (unsigned char*)malloc(len);
		size_t n_read = fread(buf, 1, len, f);
		LLVMFuzzerTestOneInput(buf, len);
		free(buf);
		fprintf(stderr, "Done:    %s: (%zd bytes)\n", argv[i], n_read);
	}
}
