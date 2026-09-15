// This file is part of witness2test,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://gitlab.com/sosy-lab/software/witness2test
//
// SPDX-FileCopyrightText: 2026 Dirk Beyer <https://www.sosy-lab.org>
//
// SPDX-License-Identifier: Apache-2.0

// Package exitcodes defines the exit codes the instrumented test program emits
// to signal validation outcomes back to witness2test. These values are the single
// source of truth: the embedded C harness, the generated injection function, and
// the verdict logic in package execution all refer to these constants.
package exitcodes

const (
	// ViolationReached is emitted from the embedded harness's reach_error()
	// when the program reaches the witnessed violation point.
	ViolationReached = 213

	// WitnessInconsistent is emitted from the generated injection function's
	// overflow branch when a witnessed nondet call site is called more times
	// than the witness supplied values for.
	WitnessInconsistent = 214
)
