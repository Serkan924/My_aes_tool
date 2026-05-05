#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"

// четене файл
unsigned char* read_file(const char *filename, long *size) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    rewind(f);

    unsigned char *buffer = malloc(*size);
    fread(buffer, 1, *size, f);
    fclose(f);

    return buffer;
}

// запис файл
void write_file(const char *filename, unsigned char *data, int size) {
    FILE *f = fopen(filename, "wb");
    fwrite(data, 1, size, f);
    fclose(f);
}

int main(int argc, char *argv[]) {

    if (argc != 6) {
        printf("Usage: enc|dec input output key iv\n");
        return 1;
    }

    char *mode = argv[1];
    long size;

    unsigned char *input = read_file(argv[2], &size);
    unsigned char output[1024 * 1024];

    int out_len;

    if (strcmp(mode, "enc") == 0) {
        out_len = encrypt(input, size,
                          (unsigned char*)argv[4],
                          (unsigned char*)argv[5],
                          output);
    } else {
        out_len = decrypt(input, size,
                          (unsigned char*)argv[4],
                          (unsigned char*)argv[5],
                          output);
    }

    write_file(argv[3], output, out_len);

    free(input);
    return 0;
}
