#include <stdlib.h>
extern int __VERIFIER_nondet_int(void);
int main() {
  int *p = malloc(sizeof(int));
  int lose = __VERIFIER_nondet_int();
  if (lose == 1) {
    p = 0;
  }
  free(p);
  return 0;
}
