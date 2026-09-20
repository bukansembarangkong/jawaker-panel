package sites

import (
	"strings"
	"testing"
)

// TestSlugsMatchSchemaConstraint verifies that validateSlug mirrors
// migrations/0014's sites_slug_safe (length 1-48, alphabet a-z0-9 and single
// internal hyphens) and that the Go and schema validators are not out of sync.
func TestSlugsMatchSchemaConstraint(t *testing.T) {
	valid := []string{
		"a",
		"z",
		"0",
		"my-site",
		"www",
		"example-01",
		strings.Repeat("a", 48),        // max length
		"a" + strings.Repeat("-a", 23), // alternating, 48 chars
	}
	for _, slug := range valid {
		if err := validateSlug(slug); err != nil {
			t.Errorf("validateSlug(%q) = %v, want nil", slug, err)
		}
	}
}

func TestSlugsRejectInvalidInputs(t *testing.T) {
	cases := []struct {
		slug   string
		reason string
	}{
		{"", "empty"},
		{strings.Repeat("a", 49), "too long"},
		{"-abc", "leading hyphen"},
		{"abc-", "trailing hyphen"},
		{"ABC", "uppercase"},
		{"a b", "space"},
		{"a/b", "slash"},
		{"a.b", "dot"},
		{"a_b", "underscore"},
		{"\n", "newline"},
	}
	for _, tc := range cases {
		if err := validateSlug(tc.slug); err == nil {
			t.Errorf("validateSlug(%q) = nil, want error (%s)", tc.slug, tc.reason)
		}
	}
}

func TestSlugsNoteShorterMinThanProjects(t *testing.T) {
	// sites_slug_length is 1..48 while projects_slug_length is 3..48.
	// A one-char slug is valid for a site and invalid for a project.
	// Keeping this test prevents the validator from accidentally being tightened
	// to the project bound.
	if err := validateSlug("a"); err != nil {
		t.Errorf("single-char slug rejected: %v; sites allow 1..48, not 3..48", err)
	}
	if err := validateSlug("ab"); err != nil {
		t.Errorf("two-char slug rejected: %v; sites allow 1..48", err)
	}
}

// TestValidateModeAllowlist verifies that only the three Phase 3 modes are
// accepted and that the check is exact.
func TestValidateModeAllowlist(t *testing.T) {
	valid := []string{ModeStatic, ModePHP, ModeReverseProxy}
	for _, m := range valid {
		if err := validateMode(m); err != nil {
			t.Errorf("validateMode(%q) = %v, want nil", m, err)
		}
	}
	invalid := []string{"", "STATIC", "node", "reverse-proxy", "container", "external", "caddy"}
	for _, m := range invalid {
		if err := validateMode(m); err == nil {
			t.Errorf("validateMode(%q) = nil, want error", m)
		}
	}
}

// TestValidateModeFieldsMirrorsSchemaChecks verifies that validateModeFields
// enforces the same rules as sites_upstream_matches_mode and
// sites_php_unit_matches_mode.
func TestValidateModeFieldsMirrorsSchemaChecks(t *testing.T) {
	cases := []struct {
		mode     string
		upstream string
		phpUnit  string
		wantErr  bool
		reason   string
	}{
		// static: no upstream, no php_unit
		{ModeStatic, "", "", false, "static with no extras"},
		{ModeStatic, "http://backend", "", true, "static with upstream"},
		{ModeStatic, "", "php8.3-fpm", true, "static with php_unit"},
		// php: no upstream, php_unit optional
		{ModePHP, "", "", false, "php with empty php_unit"},
		{ModePHP, "", "php8.3-fpm", false, "php with php_unit"},
		{ModePHP, "http://backend", "", true, "php with upstream"},
		// reverse_proxy: upstream required, no php_unit
		{ModeReverseProxy, "http://backend:3000", "", false, "proxy with upstream"},
		{ModeReverseProxy, "", "", true, "proxy without upstream"},
		{ModeReverseProxy, "http://backend:3000", "php8.3-fpm", true, "proxy with php_unit"},
	}
	for _, tc := range cases {
		err := validateModeFields(tc.mode, tc.upstream, tc.phpUnit)
		if (err != nil) != tc.wantErr {
			t.Errorf("validateModeFields(%q, %q, %q) error = %v, wantErr = %v (%s)",
				tc.mode, tc.upstream, tc.phpUnit, err, tc.wantErr, tc.reason)
		}
	}
}

// TestNullableTrimmedReturnsNilForNilPointer ensures partial updates do not
// write empty strings when the caller did not send the field.
func TestNullableTrimmedReturnsNilForNilPointer(t *testing.T) {
	if got := nullableTrimmed(nil); got != nil {
		t.Errorf("nullableTrimmed(nil) = %v, want nil", got)
	}
	s := "  hello  "
	got := nullableTrimmed(&s)
	if got == nil {
		t.Fatal("nullableTrimmed(non-nil) = nil, want trimmed value")
	}
	if got.(string) != "hello" {
		t.Errorf("nullableTrimmed = %q, want %q", got, "hello")
	}
}
