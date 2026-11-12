#include <stdlib.h>
int main() {
  int *p = malloc(2 * sizeof(long));
  volatile int index = 2;
  if (sizeof(long) == 4) {
    p[index] = 1;
  }
  free(p);
  return 0;
}
