// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
)

// FieldSet is a set of condition fields and their types, for conditions over
// something other than a gateway request (alert rules over events). Use the
// types String, Double, Int, Bool and StringList: the parser compares them by
// identity.
type FieldSet map[string]*cel.Type

// The field types of a FieldSet.
var (
	String     = cel.StringType
	Double     = cel.DoubleType
	Int        = cel.IntType
	Bool       = cel.BoolType
	StringList = listOfStrings
)

// ParseConditionIn parses condition text over fields and returns the CEL
// expression it compiles to. Refusals are *ParseError, with the position of
// the problem, as for ParseCondition.
func ParseConditionIn(text string, fields FieldSet) (string, error) {
	if fields == nil {
		return "", errors.New("no field set")
	}
	tree, err := parseCondition(text, fields)
	if err != nil {
		return "", err
	}
	expr, err := jsonASTToCELIn(tree, false, fields)
	if err != nil {
		return "", &ParseError{Message: err.Error()}
	}
	return expr, nil
}

// celIdent is the CEL variable of a FieldSet field. A field without a dot
// ("type") can clash with a CEL builtin, so every field gets a prefix and
// dots become underscores: the condition text keeps the field names.
func celIdent(field string) string { return "f_" + strings.ReplaceAll(field, ".", "__") }

// Condition is a compiled condition over a FieldSet.
type Condition struct {
	prg cel.Program
}

// CompileCondition compiles a CEL expression produced by ParseConditionIn
// with the same cost limit as policy rules. An empty expression always
// matches.
func CompileCondition(expr string, fields FieldSet) (*Condition, error) {
	if strings.TrimSpace(expr) == "" {
		return &Condition{}, nil
	}
	opts := make([]cel.EnvOption, 0, len(fields))
	for name, typ := range fields {
		opts = append(opts, cel.Variable(celIdent(name), typ))
	}
	env, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, fmt.Errorf("cel env: %w", err)
	}
	prg, err := compileWith(env, expr, costLimit)
	if err != nil {
		return nil, err
	}
	return &Condition{prg: prg}, nil
}

// Match evaluates the condition against vars, which must hold every field of
// the set. An evaluation error is returned, never a match.
func (c *Condition) Match(ctx context.Context, vars map[string]any) (bool, error) {
	if c == nil || c.prg == nil {
		return true, nil
	}
	act := make(map[string]any, len(vars))
	for k, v := range vars {
		act[celIdent(k)] = v
	}
	out, _, err := c.prg.ContextEval(ctx, act)
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("condition is not a boolean: %v", out.Value())
	}
	return b, nil
}
