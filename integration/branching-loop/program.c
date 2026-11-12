void reach_error() {}
extern int __VERIFIER_nondet_int(void);
int main() {
  int count = 0;
  while (__VERIFIER_nondet_int() > 0) {
    count++;
  }
  if (count == 2) {
    reach_error();
  }
  return 0;
}
