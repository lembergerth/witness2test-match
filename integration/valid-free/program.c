#include <stdlib.h>
extern _Bool __VERIFIER_nondet_bool(void);
int main() {
  int *p = malloc(sizeof(int));
  if (__VERIFIER_nondet_bool()) {
    free(p);
  }
  free(p);
  return 0;
}
