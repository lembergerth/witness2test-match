// This file is part of the SV-Benchmarks collection of verification tasks:
// https://gitlab.com/sosy-lab/benchmarking/sv-benchmarks
//
// SPDX-FileCopyrightText: 2015 Thomas Ströder
// SPDX-FileCopyrightText: 2015-2023 The SV-Benchmarks Community
//
// SPDX-License-Identifier: BSD-2-Clause

typedef enum {false,true} bool;

extern int __VERIFIER_nondet_int(void);

int main() {
    int i;
    i = __VERIFIER_nondet_int();

    while (i > 0) {
        if (i != 5) {
            i = i-1;
        }
    }

    return 0;
}
