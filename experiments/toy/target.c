#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int has_seq(const unsigned char *buf, size_t len,
                   const unsigned char *seq, size_t seq_len) {

  if (len < seq_len) { return 0; }
  for (size_t i = 0; i + seq_len <= len; ++i) {

    if (memcmp(buf + i, seq, seq_len) == 0) { return 1; }

  }

  return 0;

}

int main(int argc, char **argv) {

  FILE *f = stdin;
  if (argc > 1) {

    f = fopen(argv[1], "rb");
    if (!f) { return 0; }

  }

  unsigned char buf[128];
  size_t n = fread(buf, 1, sizeof(buf), f);
  if (f != stdin) { fclose(f); }

  if (n < 4) { return 0; }

  if (buf[0] == 'A' && buf[1] == 'F' && buf[2] == 'L') {

    if (n > 10 && buf[3] == '+' && buf[4] == '+') {

      if (has_seq(buf, n, (const unsigned char *)"FUZ", 3)) {

        if (has_seq(buf, n, (const unsigned char *)"EDGE", 4)) {

          volatile int x = 0;
          x += buf[5];

        }

      }

    }

  }

  if (has_seq(buf, n, (const unsigned char *)"SLOW", 4)) {

    volatile unsigned long i;
    for (i = 0; i < 1000000UL; ++i) {

      /* burn CPU */

    }

  }

  if (has_seq(buf, n, (const unsigned char *)"CRSH", 4)) {

    *(volatile int *)0 = 1;

  }

  return 0;

}
