// Command crdcompat compares two sets of generated CRD manifests and reports
// schema changes that break existing objects: a field that disappears from a
// served version, one whose type changes, or validation that an object stored
// under the old schema can fail (a new required field, a narrower enum, a new
// pattern or validation rule, a tighter bound).
//
// It exists because the graduation contract in docs/api-versioning.md depends
// on such changes being deliberate and recorded. A policy that relies on
// remembering is not a policy — the v0.11.10 rename of
// PodTraceSession.status.phase shipped in a patch release without a BREAKING
// CHANGE footer, which is exactly what this catches.
//
// The tool only reports. Whether a report is a failure is decided by the
// caller, so that a commit carrying a BREAKING CHANGE footer can proceed.
package main

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// Change is one breaking schema difference between two revisions of a CRD.
type Change struct {
	CRD     string
	Version string
	Path    string
	Kind    ChangeKind
	Detail  string
}

// ChangeKind distinguishes why a change breaks existing objects.
type ChangeKind string

const (
	FieldRemoved        ChangeKind = "field removed"
	TypeChanged         ChangeKind = "type changed"
	VersionRemoved      ChangeKind = "served version removed"
	RequiredAdded       ChangeKind = "field made required"
	EnumNarrowed        ChangeKind = "enum narrowed"
	PatternChanged      ChangeKind = "pattern changed"
	BoundTightened      ChangeKind = "bound tightened"
	ValidationRuleAdded ChangeKind = "validation rule added"
)

// lowerBounds and upperBounds are the numeric schema keywords that reject
// more values as they rise and as they fall, respectively.
var (
	lowerBounds = []string{"minimum", "minLength", "minItems", "minProperties"}
	upperBounds = []string{"maximum", "maxLength", "maxItems", "maxProperties"}
)

func (c Change) String() string {
	if c.Detail == "" {
		return fmt.Sprintf("%s: %s %s: %s", c.CRD, c.Version, c.Kind, c.Path)
	}
	return fmt.Sprintf("%s: %s %s: %s (%s)", c.CRD, c.Version, c.Kind, c.Path, c.Detail)
}

// crd is the subset of a CustomResourceDefinition this tool reads.
type crd struct {
	Metadata struct {
		Name string `json:"name"`
	} `json:"metadata"`
	Spec struct {
		Versions []struct {
			Name   string `json:"name"`
			Served bool   `json:"served"`
			Schema struct {
				OpenAPIV3Schema map[string]any `json:"openAPIV3Schema"`
			} `json:"schema"`
		} `json:"versions"`
	} `json:"spec"`
}

// field is a leaf or branch of a schema, keyed by its dotted path, with the
// validation an existing object has to keep passing.
type field struct {
	openAPIType      string
	intOrString      bool
	enum             []string
	pattern          string
	bounds           map[string]float64
	exclusiveMinimum bool
	exclusiveMaximum bool
	required         []string
	defaulted        map[string]bool
	rules            []string
}

// Compare reports the breaking differences between the old and new revision of
// a single CRD manifest. Additions are not breaking and are not reported.
func Compare(oldYAML, newYAML []byte) ([]Change, error) {
	oldCRD, err := parse(oldYAML)
	if err != nil {
		return nil, fmt.Errorf("parsing previous revision: %w", err)
	}
	newCRD, err := parse(newYAML)
	if err != nil {
		return nil, fmt.Errorf("parsing new revision: %w", err)
	}

	name := newCRD.Metadata.Name
	if name == "" {
		name = oldCRD.Metadata.Name
	}

	var changes []Change
	newVersions := servedSchemas(newCRD)
	for version, oldFields := range servedSchemas(oldCRD) {
		newFields, ok := newVersions[version]
		if !ok {
			changes = append(changes, Change{
				CRD:     name,
				Version: version,
				Kind:    VersionRemoved,
				Path:    version,
				Detail:  "requires a storage migration first",
			})
			continue
		}
		changes = append(changes, compareFields(name, version, oldFields, newFields)...)
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Version != changes[j].Version {
			return changes[i].Version < changes[j].Version
		}
		return changes[i].Path < changes[j].Path
	})
	return changes, nil
}

func compareFields(crdName, version string, oldFields, newFields map[string]field) []Change {
	var changes []Change
	for path, oldField := range oldFields {
		newField, ok := newFields[path]
		if !ok {
			changes = append(changes, Change{
				CRD:     crdName,
				Version: version,
				Kind:    FieldRemoved,
				Path:    path,
			})
			continue
		}
		if oldField.openAPIType != "" && newField.openAPIType != "" &&
			oldField.openAPIType != newField.openAPIType {
			changes = append(changes, Change{
				CRD:     crdName,
				Version: version,
				Kind:    TypeChanged,
				Path:    path,
				Detail:  oldField.openAPIType + " -> " + newField.openAPIType,
			})
		}
		if oldField.intOrString && !newField.intOrString {
			changes = append(changes, Change{
				CRD:     crdName,
				Version: version,
				Kind:    TypeChanged,
				Path:    path,
				Detail:  "int-or-string -> " + orUnset(newField.openAPIType),
			})
		}
		for _, c := range tightenedValidation(path, oldField, newField) {
			c.CRD, c.Version = crdName, version
			changes = append(changes, c)
		}
	}
	return changes
}

// tightenedValidation reports validation an object accepted by oldField can
// fail under newField.
func tightenedValidation(path string, oldField, newField field) []Change {
	var changes []Change

	for _, name := range newField.required {
		if slices.Contains(oldField.required, name) || newField.defaulted[name] {
			continue
		}
		changes = append(changes, Change{Kind: RequiredAdded, Path: join(path, name)})
	}

	if newField.enum != nil {
		var dropped []string
		for _, v := range oldField.enum {
			if !slices.Contains(newField.enum, v) {
				dropped = append(dropped, v)
			}
		}
		switch {
		case oldField.enum == nil:
			changes = append(changes, Change{Kind: EnumNarrowed, Path: path, Detail: "enum added"})
		case len(dropped) > 0:
			changes = append(changes, Change{Kind: EnumNarrowed, Path: path, Detail: "dropped " + strings.Join(dropped, ", ")})
		}
	}

	if newField.pattern != "" && newField.pattern != oldField.pattern {
		changes = append(changes, Change{Kind: PatternChanged, Path: path, Detail: orUnset(oldField.pattern) + " -> " + newField.pattern})
	}

	for _, key := range lowerBounds {
		if detail, tighter := boundChange(key, oldField.bounds, newField.bounds, func(o, n float64) bool { return n > o }); tighter {
			changes = append(changes, Change{Kind: BoundTightened, Path: path, Detail: detail})
		}
	}
	for _, key := range upperBounds {
		if detail, tighter := boundChange(key, oldField.bounds, newField.bounds, func(o, n float64) bool { return n < o }); tighter {
			changes = append(changes, Change{Kind: BoundTightened, Path: path, Detail: detail})
		}
	}
	if newField.exclusiveMinimum && !oldField.exclusiveMinimum {
		changes = append(changes, Change{Kind: BoundTightened, Path: path, Detail: "exclusiveMinimum"})
	}
	if newField.exclusiveMaximum && !oldField.exclusiveMaximum {
		changes = append(changes, Change{Kind: BoundTightened, Path: path, Detail: "exclusiveMaximum"})
	}

	for _, rule := range newField.rules {
		if !slices.Contains(oldField.rules, rule) {
			changes = append(changes, Change{Kind: ValidationRuleAdded, Path: path, Detail: rule})
		}
	}
	return changes
}

// boundChange reports whether key moved in the rejecting direction, counting
// a bound that did not exist before as a tightening.
func boundChange(key string, oldBounds, newBounds map[string]float64, tighter func(o, n float64) bool) (string, bool) {
	n, hasNew := newBounds[key]
	if !hasNew {
		return "", false
	}
	o, hasOld := oldBounds[key]
	if !hasOld {
		return fmt.Sprintf("%s %g added", key, n), true
	}
	if tighter(o, n) {
		return fmt.Sprintf("%s %g -> %g", key, o, n), true
	}
	return "", false
}

func join(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

func orUnset(s string) string {
	if s == "" {
		return "unset"
	}
	return s
}

func parse(data []byte) (*crd, error) {
	var c crd
	if err := yaml.Unmarshal(stripTemplateLines(data), &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// stripTemplateLines drops the Helm control lines that
// hack/inject-crd-annotations.sh wraps around each generated manifest, so the
// committed chart templates can be parsed as plain YAML.
func stripTemplateLines(data []byte) []byte {
	lines := strings.Split(string(data), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "{{") {
			continue
		}
		kept = append(kept, line)
	}
	return []byte(strings.Join(kept, "\n"))
}

// servedSchemas flattens each served version's schema into dotted field paths.
// Unserved versions are skipped: nothing reads them, so changing them breaks
// nobody.
func servedSchemas(c *crd) map[string]map[string]field {
	out := map[string]map[string]field{}
	for _, v := range c.Spec.Versions {
		if !v.Served {
			continue
		}
		fields := map[string]field{}
		if root := v.Schema.OpenAPIV3Schema; root != nil {
			fields[""] = describe(root)
		}
		walk("", v.Schema.OpenAPIV3Schema, fields)
		out[v.Name] = fields
	}
	return out
}

// walk descends a structural schema, recording one entry per addressable
// field. Array element schemas are recorded under the array's own path with a
// "[]" suffix so that a type change inside a list is still visible.
func walk(prefix string, schema map[string]any, out map[string]field) {
	if schema == nil {
		return
	}

	if properties, ok := schema["properties"].(map[string]any); ok {
		for name, raw := range properties {
			child, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			path := join(prefix, name)
			out[path] = describe(child)
			walk(path, child, out)
		}
	}

	if items, ok := schema["items"].(map[string]any); ok && prefix != "" {
		path := prefix + "[]"
		out[path] = describe(items)
		walk(path, items, out)
	}

	if additional, ok := schema["additionalProperties"].(map[string]any); ok && prefix != "" {
		path := prefix + "{}"
		out[path] = describe(additional)
		walk(path, additional, out)
	}
}

// describe records the validation one schema node applies to its own value.
func describe(schema map[string]any) field {
	f := field{
		openAPIType:      stringValue(schema, "type"),
		pattern:          stringValue(schema, "pattern"),
		intOrString:      schema["x-kubernetes-int-or-string"] == true,
		exclusiveMinimum: schema["exclusiveMinimum"] == true,
		exclusiveMaximum: schema["exclusiveMaximum"] == true,
		bounds:           map[string]float64{},
		defaulted:        map[string]bool{},
	}
	if values, ok := schema["enum"].([]any); ok {
		f.enum = make([]string, 0, len(values))
		for _, v := range values {
			f.enum = append(f.enum, fmt.Sprint(v))
		}
	}
	for _, key := range append(slices.Clone(lowerBounds), upperBounds...) {
		if n, ok := number(schema[key]); ok {
			f.bounds[key] = n
		}
	}
	if names, ok := schema["required"].([]any); ok {
		for _, n := range names {
			if name, ok := n.(string); ok {
				f.required = append(f.required, name)
			}
		}
	}
	if properties, ok := schema["properties"].(map[string]any); ok {
		for name, raw := range properties {
			if child, ok := raw.(map[string]any); ok {
				if _, has := child["default"]; has {
					f.defaulted[name] = true
				}
			}
		}
	}
	if rules, ok := schema["x-kubernetes-validations"].([]any); ok {
		for _, raw := range rules {
			if rule, ok := raw.(map[string]any); ok {
				if r := stringValue(rule, "rule"); r != "" {
					f.rules = append(f.rules, r)
				}
			}
		}
	}
	return f
}

// number reads a numeric keyword. Manifests are decoded through JSON, so every
// number arrives as a float64.
func number(v any) (float64, bool) {
	n, ok := v.(float64)
	return n, ok
}

func stringValue(m map[string]any, key string) string {
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

// Report renders changes as a newline-terminated block, most significant
// first, suitable for a CI annotation.
func Report(changes []Change) string {
	var b strings.Builder
	for _, c := range changes {
		b.WriteString(c.String())
		b.WriteString("\n")
	}
	return b.String()
}
