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
	"sort"
	"strconv"
	"strings"

	"witness2test/witness"
)

// dataModel is the data model of the program under test.
type dataModel int

const (
	modelLP64 dataModel = iota
	modelILP32
)

func parseDataModel(name string) (dataModel, error) {
	switch name {
	case "", "LP64":
		return modelLP64, nil
	case "ILP32":
		return modelILP32, nil
	}
	return modelLP64, fmt.Errorf("invalid data model %q: expected ILP32 or LP64", name)
}

// matcher finds the nondet call sites that assumption and branching
// waypoints determine the values of.
type matcher struct {
	src        *sourceText
	sites      map[siteStart]NondetCallSite
	model      dataModel
	constructs map[witness.Location]foundConstruct
}

// siteStart identifies a call site by its line and the 0-based column of the
// first character of the call.
type siteStart struct {
	line    int
	column0 int
}

func newMatcher(program string, sites []NondetCallSite, model dataModel) *matcher {
	m := &matcher{
		src:        newSourceText(program),
		sites:      make(map[siteStart]NondetCallSite, len(sites)),
		model:      model,
		constructs: make(map[witness.Location]foundConstruct),
	}
	for _, s := range sites {
		m.sites[siteStart{line: s.Line, column0: s.column0}] = s
	}
	return m
}

// siteAt returns the call site that spans exactly the 0-based columns
// [start0, end0) of the line.
func (m *matcher) siteAt(line, start0, end0 int) (NondetCallSite, bool) {
	site, ok := m.sites[siteStart{line: line, column0: start0}]
	if !ok || site.endIdx0 != end0 {
		return NondetCallSite{}, false
	}
	return site, true
}

// note is a message about a waypoint, with the position it is sorted by.
type note struct {
	loc  witness.Location
	text string
}

// sortedNotes returns the texts ordered by line and column. Notes for the
// same position keep the order in which they were added.
func sortedNotes(notes []note) []string {
	sort.SliceStable(notes, func(i, j int) bool {
		if notes[i].loc.Line != notes[j].loc.Line {
			return notes[i].loc.Line < notes[j].loc.Line
		}
		return notes[i].loc.Column < notes[j].loc.Column
	})
	var texts []string
	for _, n := range notes {
		texts = append(texts, n.text)
	}
	return texts
}

// formatLocation renders a witness location; the column is omitted if the
// witness does not specify it.
func formatLocation(loc witness.Location) string {
	if loc.Column == 0 {
		return strconv.Itoa(loc.Line)
	}
	return fmt.Sprintf("%d:%d", loc.Line, loc.Column)
}

func siteLocation(site NondetCallSite) witness.Location {
	return witness.Location{Line: site.Line, Column: site.ColumnOfClosingParen}
}

// derivedValues collects the values per call site of one strategy, with the
// sites in the order in which they were first seen.
type derivedValues struct {
	bySite map[witness.Location]*witnessedSite
	order  []witness.Location
}

func (d *derivedValues) add(site NondetCallSite, values ...string) {
	if d.bySite == nil {
		d.bySite = make(map[witness.Location]*witnessedSite)
	}
	key := siteLocation(site)
	ws, ok := d.bySite[key]
	if !ok {
		ws = &witnessedSite{site: site}
		d.bySite[key] = ws
		d.order = append(d.order, key)
	}
	ws.values = append(ws.values, values...)
}

// deriveValues turns assumption and branching waypoints into values for the
// nondet call sites that have no function_return values. A call site gets
// its values from one kind of waypoint only: function_return waypoints win
// over assumptions, and assumptions win over branchings. The returned notes
// name the waypoints that were not used.
func deriveValues(program string, sites []NondetCallSite, withFunctionReturn []witnessedSite, w *witness.Witness, model dataModel) ([]witnessedSite, []string) {
	if len(w.Assumptions) == 0 && len(w.Branchings) == 0 {
		return nil, nil
	}
	m := newMatcher(program, sites, model)
	// valueSource names the kind of waypoint a call site has its values from.
	valueSource := make(map[witness.Location]string)
	for _, ws := range withFunctionReturn {
		valueSource[siteLocation(ws.site)] = "function_return"
	}
	var notes []note
	var result []witnessedSite

	var fromAssumptions derivedValues
	for _, a := range w.Assumptions {
		description := fmt.Sprintf("assumption at %s (%s == %s)", formatLocation(a.Loc), a.Variable, a.Value)
		site, reason := m.matchAssumption(a)
		if reason != "" {
			notes = append(notes, note{a.Loc, description + " not matched: " + reason})
			continue
		}
		if source, taken := valueSource[siteLocation(site)]; taken {
			notes = append(notes, note{a.Loc, description + " not used: " + reasonSiteTaken(site, source)})
			continue
		}
		fromAssumptions.add(site, a.Value)
	}
	for _, key := range fromAssumptions.order {
		valueSource[key] = "assumption"
		result = append(result, *fromAssumptions.bySite[key])
	}

	fromBranchings, branchingNotes := m.matchBranchings(w.Branchings, valueSource)
	result = append(result, fromBranchings...)
	notes = append(notes, branchingNotes...)

	return result, sortedNotes(notes)
}

// nondetPrefix starts the name of every nondet function.
const nondetPrefix = "__VERIFIER_nondet_"

// branchingGroup collects the branching waypoints that refer to the same
// construct, in document order.
type branchingGroup struct {
	construct construct
	waypoints []witness.Branching
	// Set by resolve:
	site   NondetCallSite
	values []string
}

// matchBranchings turns branching waypoints into values for the nondet call
// in the controlling expression of their construct.
//
// The values of a call site are consumed one per call. Therefore, a
// construct is used only if every one of its waypoints yields a value, and
// only if no other construct or kind of waypoint provides values for the
// same call site (valueSource names the call sites that have values already).
func (m *matcher) matchBranchings(branchings []witness.Branching, valueSource map[witness.Location]string) ([]witnessedSite, []note) {
	var notes []note
	groups := make(map[int]*branchingGroup)
	var order []*branchingGroup
	for _, b := range branchings {
		c, reason := m.findConstruct(b.Loc)
		if reason != "" {
			notes = append(notes, note{b.Loc, fmt.Sprintf("branching at %s (%s) not matched: %s", formatLocation(b.Loc), b.Value, reason)})
			continue
		}
		g, ok := groups[c.pos]
		if !ok {
			g = &branchingGroup{construct: c}
			groups[c.pos] = g
			order = append(order, g)
		}
		g.waypoints = append(g.waypoints, b)
	}

	describe := func(g *branchingGroup) (witness.Location, string) {
		line, column := m.src.position(g.construct.pos)
		loc := witness.Location{Line: line, Column: column}
		kind := g.construct.kind
		if kind == "?" {
			kind = "?:"
		}
		plural := "s"
		if len(g.waypoints) == 1 {
			plural = ""
		}
		return loc, fmt.Sprintf("branching at %s (%s, %d waypoint%s)", formatLocation(loc), kind, len(g.waypoints), plural)
	}

	var resolved []*branchingGroup
	constructsPerSite := make(map[witness.Location]int)
	for _, g := range order {
		loc, description := describe(g)
		if !strings.Contains(m.src.masked[g.construct.exprStart:g.construct.exprEnd], nondetPrefix) {
			// The condition involves no nondet call, so the waypoint says
			// nothing about input values. Most waypoints are of this kind;
			// they are not worth a note.
			continue
		}
		if reason := m.resolve(g); reason != "" {
			notes = append(notes, note{loc, description + " not matched: " + reason})
			continue
		}
		if source, taken := valueSource[siteLocation(g.site)]; taken {
			notes = append(notes, note{loc, description + " not used: " + reasonSiteTaken(g.site, source)})
			continue
		}
		resolved = append(resolved, g)
		constructsPerSite[siteLocation(g.site)]++
	}

	var result []witnessedSite
	for _, g := range resolved {
		if constructsPerSite[siteLocation(g.site)] > 1 {
			loc, description := describe(g)
			notes = append(notes, note{loc, fmt.Sprintf("%s not matched: several branching constructs refer to the nondet call site at %s",
				description, formatLocation(siteLocation(g.site)))})
			continue
		}
		result = append(result, witnessedSite{site: g.site, values: g.values})
	}
	return result, notes
}

const reasonUnknownConditionCallSite = "the nondet call of the controlling expression is not a recognized call site"

// resolve determines the call site and the values for a construct and its
// waypoints. If the construct cannot be used, reason says why; it is empty
// on success.
func (m *matcher) resolve(g *branchingGroup) (reason string) {
	cond, reason := analyzeCondition(m.src, g.construct.exprStart, g.construct.exprEnd)
	if reason != "" {
		return reason
	}
	// The controlling expression is on one line, and so is the call.
	line, column := m.src.position(cond.callStart)
	site, ok := m.siteAt(line, column-1, column-1+cond.callEnd-cond.callStart)
	if !ok {
		return reasonUnknownConditionCallSite
	}
	values := make([]string, 0, len(g.waypoints))
	for _, b := range g.waypoints {
		value, reason := cond.valueFor(g.construct.kind, b.Value, m.model)
		if reason != "" {
			return reason
		}
		values = append(values, value)
	}
	g.site, g.values = site, values
	return ""
}

func reasonSiteTaken(site NondetCallSite, source string) string {
	return fmt.Sprintf("the nondet call site at %s has values from %s waypoints", formatLocation(siteLocation(site)), source)
}
