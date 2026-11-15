extern void abort(void);
void reach_error() { abort(); }
int main() {
  volatile float a = 1.0f, b = 3.0f;
  volatile float quotient = a / b;
  if (quotient != a / b) {
    reach_error();
  }
  return 0;
}
