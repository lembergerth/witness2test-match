// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
// SPDX-License-Identifier: Apache-2.0

void reach_error(){}
extern int __VERIFIER_nondet_int(void);

int main() {
  int x = __VERIFIER_nondet_int();
  if (x == 42) {
    reach_error();
    return 1;
  }
  return 0;
}
