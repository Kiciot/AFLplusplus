// target.c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

static void sink(volatile uint32_t x) { (void)x; }

int main(void) {
  uint8_t buf[4096];
  size_t n = fread(buf, 1, sizeof(buf), stdin);
  if (n < 4) return 0;

  // 这里是多分支，会产生“新覆盖”
  if (buf[0] == 'P') {
    if (buf[1] == 'N') {
      if (buf[2] == 'G') sink(1);
      if (buf[2] == 'X') sink(2);
    }
    if (buf[1] == 'D') {
      if (buf[2] == 'F') sink(3);
    }
  }

  if (buf[0] == 0xFF && buf[1] == 0xD8) { // JPEG magic
    if (n > 100 && buf[99] == 0x00) sink(4);
  }

  // 一个“可能崩溃点”（用于后续验证 crash 捕获，不是必须）
  if (n > 8 && buf[0] == 'C' && buf[1] == 'R' && buf[2] == 'A' && buf[3] == 'S') {
    volatile uint8_t *p = NULL;
    *p = 1; // crash
  }

  return 0;
}
