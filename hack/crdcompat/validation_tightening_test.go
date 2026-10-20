package main

import (
	"strings"
	"testing"
)

func compareSpec(t *testing.T, before, after string) []Change {
	t.Helper()
	changes, err := Compare(
		crdYAML(oneVersion("v1alpha1", true, before)),
		crdYAML(oneVersion("v1alpha1", true, after)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return changes
}

func TestMakingAnExistingFieldRequiredIsBreaking(t *testing.T) {
	changes := compareSpec(t, `          spec:
            type: object
            properties:
              image: {type: string}
`, `          spec:
            type: object
            required: [image]
            properties:
              image: {type: string}
`)
	requireChanges(t, changes, "field made required spec.image")
}

func TestANewRequiredFieldWithADefaultIsNotBreaking(t *testing.T) {
	changes := compareSpec(t, `          spec:
            type: object
            properties:
              image: {type: string}
`, `          spec:
            type: object
            required: [mode]
            properties:
              image: {type: string}
              mode: {type: string, default: auto}
`)
	requireChanges(t, changes)
}

func TestARequiredTopLevelFieldIsBreaking(t *testing.T) {
	changes, err := Compare(
		crdYAML(oneVersion("v1alpha1", true, `          spec: {type: object}
`)),
		crdYAML(strings.Replace(oneVersion("v1alpha1", true, `          spec: {type: object}
`), "        type: object\n", "        type: object\n        required: [spec]\n", 1)),
	)
	if err != nil {
		t.Fatal(err)
	}
	requireChanges(t, changes, "field made required spec")
}

func TestNarrowingAnEnumIsBreaking(t *testing.T) {
	changes := compareSpec(t, `          spec:
            type: object
            properties:
              mode: {type: string, enum: [auto, file, embedded]}
`, `          spec:
            type: object
            properties:
              mode: {type: string, enum: [auto, file]}
`)
	requireChanges(t, changes, "enum narrowed spec.mode")
	if changes[0].Detail != "dropped embedded" {
		t.Errorf("detail = %q, want the dropped value named", changes[0].Detail)
	}
}

func TestWideningAnEnumIsNotBreaking(t *testing.T) {
	changes := compareSpec(t, `          spec:
            type: object
            properties:
              mode: {type: string, enum: [auto]}
`, `          spec:
            type: object
            properties:
              mode: {type: string, enum: [auto, file]}
`)
	requireChanges(t, changes)
}

func TestAddingAnEnumToAFreeFieldIsBreaking(t *testing.T) {
	changes := compareSpec(t, `          spec:
            type: object
            properties:
              mode: {type: string}
`, `          spec:
            type: object
            properties:
              mode: {type: string, enum: [auto]}
`)
	requireChanges(t, changes, "enum narrowed spec.mode")
}

func TestAddingOrChangingAPatternIsBreaking(t *testing.T) {
	changes := compareSpec(t, `          spec:
            type: object
            properties:
              name: {type: string}
              host: {type: string, pattern: "^[a-z.]+$"}
`, `          spec:
            type: object
            properties:
              name: {type: string, pattern: "^[a-z]+$"}
              host: {type: string, pattern: "^[a-z]+$"}
`)
	requireChanges(t, changes, "pattern changed spec.host", "pattern changed spec.name")
}

func TestTighterBoundsAreBreakingAndLooserOnesAreNot(t *testing.T) {
	changes := compareSpec(t, `          spec:
            type: object
            properties:
              percent: {type: integer, minimum: 0, maximum: 100}
              name: {type: string, maxLength: 63}
              items: {type: array, maxItems: 10, items: {type: string}}
`, `          spec:
            type: object
            properties:
              percent: {type: integer, minimum: 1, maximum: 200}
              name: {type: string, maxLength: 32, minLength: 1}
              items: {type: array, maxItems: 20, items: {type: string}}
`)
	requireChanges(t, changes,
		"bound tightened spec.name",
		"bound tightened spec.name",
		"bound tightened spec.percent",
	)
}

func TestIntOrStringBecomingStringIsBreaking(t *testing.T) {
	changes := compareSpec(t, `          spec:
            type: object
            properties:
              maxUnavailable:
                anyOf: [{type: integer}, {type: string}]
                x-kubernetes-int-or-string: true
`, `          spec:
            type: object
            properties:
              maxUnavailable: {type: string}
`)
	requireChanges(t, changes, "type changed spec.maxUnavailable")
	if changes[0].Detail != "int-or-string -> string" {
		t.Errorf("detail = %q", changes[0].Detail)
	}
}

func TestANewValidationRuleIsBreaking(t *testing.T) {
	changes := compareSpec(t, `          spec:
            type: object
            properties:
              image: {type: string}
`, `          spec:
            type: object
            properties:
              image:
                type: string
                x-kubernetes-validations:
                  - rule: self.contains('/')
                    message: needs a registry
`)
	requireChanges(t, changes, "validation rule added spec.image")
}

func TestUnchangedValidationIsNotReported(t *testing.T) {
	spec := `          spec:
            type: object
            required: [image]
            properties:
              image:
                type: string
                pattern: "^[a-z]+$"
                maxLength: 10
                x-kubernetes-validations:
                  - rule: self.size() > 0
              mode: {type: string, enum: [a, b]}
`
	requireChanges(t, compareSpec(t, spec, spec))
}

func TestMakingABoundExclusiveIsBreaking(t *testing.T) {
	changes := compareSpec(t, `          spec:
            type: object
            properties:
              low: {type: integer, minimum: 0}
              high: {type: integer, maximum: 10}
`, `          spec:
            type: object
            properties:
              low: {type: integer, minimum: 0, exclusiveMinimum: true}
              high: {type: integer, maximum: 10, exclusiveMaximum: true}
`)
	requireChanges(t, changes, "bound tightened spec.high", "bound tightened spec.low")
}

func TestANonNumericBoundIsIgnored(t *testing.T) {
	if _, ok := number("10"); ok {
		t.Error("a string bound was read as a number")
	}
}
