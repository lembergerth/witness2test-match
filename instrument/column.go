// This file is part of witness2test-match,
// a tool to turn SV-COMP violation witnesses (format v2) into executable tests.
// https://github.com/lembergerth/witness2test-match
//
// SPDX-FileCopyrightText: 2026 Thomas Lemberger <https://thomaslemberger.com>
//
// SPDX-License-Identifier: Apache-2.0

package instrument

import (
	"fmt"

	"witness2test/witness"
)

// resolveMissingColumns gives each injection point without column (column 0)
// the column of the only nondet call on its line. A point on a line without
// nondet call keeps column 0; it is on the call of another function.
//
// If a line without column has several nondet calls, the values cannot be
// assigned to calls, and unsupported describes the first such line. Dropping
// only these values would give the later values of the calls to the wrong
// calls. The order of points is kept; the input is not changed.
func resolveMissingColumns(points []witness.InjectionPoint, sites []NondetCallSite) (resolved []witness.InjectionPoint, unsupported string) {
	sitesPerLine := make(map[int][]NondetCallSite)
	for _, s := range sites {
		sitesPerLine[s.Line] = append(sitesPerLine[s.Line], s)
	}
	if len(points) == 0 {
		return nil, ""
	}
	resolved = make([]witness.InjectionPoint, len(points))
	for i, p := range points {
		if p.Loc.Column == 0 {
			switch onLine := sitesPerLine[p.Loc.Line]; len(onLine) {
			case 0:
			case 1:
				p.Loc.Column = onLine[0].ColumnOfClosingParen
			default:
				return nil, fmt.Sprintf("function_return waypoint at line %d has no column, and the line has %d __VERIFIER_nondet_X() calls",
					p.Loc.Line, len(onLine))
			}
		}
		resolved[i] = p
	}
	return resolved, ""
}
