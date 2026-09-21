package apps

import (
	"errors"
	"testing"
)

func TestValidateSlug(t *testing.T) {
	cases := []struct {
		slug  string
		valid bool
	}{
		{"app", true},
		{"my-node-app", true},
		{"app-1", true},
		// Double hyphens are permitted by the slug regex — the same convention
		// migrations/0014 uses for projects and sites (^[a-z0-9]([a-z0-9-]*[a-z0-9])?$).
		{"my--app", true},
		{"a", false},        // too short (< 3)
		{"ab", false},       // too short (< 3)
		{"-app", false},     // leading hyphen
		{"app-", false},     // trailing hyphen
		{"My-App", false},   // uppercase
		{"app_1", false},    // underscore
		{"app/sub", false},  // slash
		{"app..foo", false}, // dots
	}

	for _, tc := range cases {
		t.Run(tc.slug, func(t *testing.T) {
			err := validateSlug(tc.slug)
			if tc.valid && err != nil {
				t.Fatalf("expected valid slug %q, got: %v", tc.slug, err)
			}
			if !tc.valid && err == nil {
				t.Fatalf("expected invalid slug %q, got nil error", tc.slug)
			}
			if !tc.valid && !errors.Is(err, ErrInvalid) {
				t.Fatalf("expected ErrInvalid wrapping, got: %v", err)
			}
		})
	}
}

func TestValidateRuntimeType(t *testing.T) {
	for _, rt := range []string{RuntimeNode, RuntimeBun, RuntimePython, RuntimePHP, RuntimeStatic} {
		if err := validateRuntimeType(rt); err != nil {
			t.Fatalf("expected valid runtime %q, got: %v", rt, err)
		}
	}
	for _, invalid := range []string{"docker", "ruby", "go", "", "NODE"} {
		if err := validateRuntimeType(invalid); err == nil {
			t.Fatalf("expected error for invalid runtime %q, got nil", invalid)
		}
	}
}

func TestEnvNameRegex(t *testing.T) {
	cases := []struct {
		name  string
		valid bool
	}{
		{"NODE_ENV", true},
		{"PORT", true},
		{"_PRIVATE", true},
		{"API_KEY_V1", true},
		{"a", true},
		{"1PORT", false},   // starts with digit
		{"MY-VAR", false},  // hyphen not allowed in shell env names
		{"MY VAR", false},  // space
		{"VAR=VAL", false}, // equals
		{"", false},        // empty
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matched := envNameRE.MatchString(tc.name)
			if matched != tc.valid {
				t.Fatalf("name %q: expected match=%v, got %v", tc.name, tc.valid, matched)
			}
		})
	}
}

func TestMarshalArgs(t *testing.T) {
	b, err := marshalArgs(nil)
	if err != nil || string(b) != "[]" {
		t.Fatalf("nil args: got %s, err: %v", string(b), err)
	}
	b, err = marshalArgs([]string{"start", "--port", "3000"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	expected := `["start","--port","3000"]`
	if string(b) != expected {
		t.Fatalf("expected %s, got %s", expected, string(b))
	}
}
