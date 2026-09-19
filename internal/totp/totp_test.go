package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 4226 §5.4 test values, with the standard ASCII secret "12345678901234567890".
// TOTP at a 30-second period produces the same code as HOTP at counter = time/30,
// so these vectors pin both the truncation and the counter encoding.
//
//nolint:gosec // published RFC 4226 test vector, not a credential
const rfcSecretB32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestRFC4226Vectors(t *testing.T) {
	cfg := Config{Algorithm: AlgorithmSHA1, Digits: Digits6, Period: DefaultPeriod}
	want := []string{"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489"}

	for step, expected := range want {
		got, err := Code(rfcSecretB32, int64(step), cfg)
		if err != nil {
			t.Fatalf("step %d: %v", step, err)
		}
		if got != expected {
			t.Errorf("step %d = %q, want %q", step, got, expected)
		}
	}
}

// RFC 6238 Appendix B vectors, 8 digits, SHA-1. These pin the time-step
// derivation against real epoch times rather than hand-chosen counters.
func TestRFC6238Vectors(t *testing.T) {
	cfg := Config{Algorithm: AlgorithmSHA1, Digits: Digits8, Period: DefaultPeriod}
	cases := []struct {
		seconds int64
		want    string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, tc := range cases {
		at := time.Unix(tc.seconds, 0).UTC()
		got, err := Code(rfcSecretB32, StepFor(at, cfg), cfg)
		if err != nil {
			t.Fatalf("t=%d: %v", tc.seconds, err)
		}
		if got != tc.want {
			t.Errorf("t=%d code = %q, want %q", tc.seconds, got, tc.want)
		}
	}
}

// SHA-256 and SHA-512 use longer standard test secrets (RFC 6238 §4); the
// vectors below confirm the algorithm switch changes the derived code and that
// each matches its published value.
func TestRFC6238AlternateAlgorithms(t *testing.T) {
	cases := []struct {
		algorithm Algorithm
		secretB32 string
		want      string
	}{
		// "12345678901234567890123456789012" (32 bytes)
		{AlgorithmSHA256, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA", "46119246"},
		// "1234567890123456789012345678901234567890123456789012345678901234" (64 bytes)
		{AlgorithmSHA512, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA=", "90693936"},
	}
	for _, tc := range cases {
		t.Run(string(tc.algorithm), func(t *testing.T) {
			cfg := Config{Algorithm: tc.algorithm, Digits: Digits8, Period: DefaultPeriod}
			got, err := Code(tc.secretB32, StepFor(time.Unix(59, 0), cfg), cfg)
			if err != nil {
				t.Fatalf("Code: %v", err)
			}
			if got != tc.want {
				t.Errorf("code = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidateAcceptsCurrentStep(t *testing.T) {
	now := time.Unix(1111111109, 0).UTC()
	code, err := Code(rfcSecretB32, StepFor(now, DefaultConfig()), DefaultConfig())
	if err != nil {
		t.Fatalf("Code: %v", err)
	}

	step, err := Validate(rfcSecretB32, code, now)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if step != StepFor(now, DefaultConfig()) {
		t.Errorf("step = %d, want %d", step, StepFor(now, DefaultConfig()))
	}
}

// Clock skew is the reason a tolerance window exists: a phone that is 20 seconds
// behind would otherwise reject a perfectly good code, making the feature
// unusable. One step either side is standard.
func TestValidateAcceptsAdjacentSteps(t *testing.T) {
	now := time.Unix(1111111109, 0).UTC()
	cfg := DefaultConfig()
	center := StepFor(now, cfg)

	for _, offset := range []int64{-1, 0, 1} {
		code, err := Code(rfcSecretB32, center+offset, cfg)
		if err != nil {
			t.Fatalf("Code(offset %d): %v", offset, err)
		}
		step, err := ValidateWith(rfcSecretB32, code, now, cfg)
		if err != nil {
			t.Errorf("offset %+d rejected: %v", offset, err)
			continue
		}
		if step != center+offset {
			t.Errorf("offset %+d matched step %d, want %d", offset, step, center+offset)
		}
	}

	// Two steps away is outside a skew of 1.
	far, err := Code(rfcSecretB32, center+2, cfg)
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	if _, err := ValidateWith(rfcSecretB32, far, now, cfg); err == nil {
		t.Error("code two steps away accepted")
	}
}

// The returned step is what makes replay prevention possible, so a code from a
// PREVIOUS step must report its own step, not the current one. Without that, a
// caller would record the wrong step and leave the window open.
func TestValidateReportsTheMatchedStepNotTheCurrentOne(t *testing.T) {
	now := time.Unix(1111111109, 0).UTC()
	cfg := DefaultConfig()
	center := StepFor(now, cfg)

	oldCode, err := Code(rfcSecretB32, center-1, cfg)
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	step, err := ValidateWith(rfcSecretB32, oldCode, now, cfg)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if step != center-1 {
		t.Errorf("matched step = %d, want %d (the code's own step)", step, center-1)
	}
}

func TestValidateRejectsWrongCode(t *testing.T) {
	now := time.Unix(1111111109, 0).UTC()
	correct, err := Code(rfcSecretB32, StepFor(now, DefaultConfig()), DefaultConfig())
	if err != nil {
		t.Fatalf("Code: %v", err)
	}

	// A single-digit mutation must fail; this is the property the whole scheme
	// rests on.
	mutated := correct[:5] + string([]byte{correct[5] + 1})
	if mutated == correct {
		mutated = correct[:5] + string([]byte{correct[5] - 1})
	}
	if _, err := Validate(rfcSecretB32, mutated, now); err == nil {
		t.Errorf("mutated code %q accepted", mutated)
	}
}

// Input hygiene: wrong length and non-digits are rejected BEFORE any HMAC work,
// which also prevents padding tricks from making a short code compare equal.
func TestValidateRejectsMalformedInput(t *testing.T) {
	now := time.Unix(1111111109, 0).UTC()
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "12 34 56", "-12345"} {
		if _, err := Validate(rfcSecretB32, bad, now); err == nil {
			t.Errorf("code %q accepted", bad)
		}
	}
	// Whitespace around a valid code is tolerated: users paste from SMS.
	valid, err := Code(rfcSecretB32, StepFor(now, DefaultConfig()), DefaultConfig())
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	if _, err := Validate(rfcSecretB32, "  "+valid+"  ", now); err != nil {
		t.Errorf("padded valid code rejected: %v", err)
	}
}

func TestValidateRejectsBadSecret(t *testing.T) {
	now := time.Unix(1111111109, 0).UTC()
	for _, bad := range []string{"", "!!!!", "not base32 @@"} {
		if _, err := Validate(bad, "123456", now); err == nil {
			t.Errorf("secret %q accepted", bad)
		}
	}
}

// Transcription tolerance: users type lowercase and insert spaces from the
// printed card, and rejecting those for a formatting reason helps nobody.
func TestDecodeSecretToleratesHumanFormatting(t *testing.T) {
	canonical := rfcSecretB32
	cfg := DefaultConfig()
	want, err := Code(canonical, 1, cfg)
	if err != nil {
		t.Fatalf("Code: %v", err)
	}

	// Insert spaces and lowercase it.
	spaced := strings.ToLower(canonical[:4] + " " + canonical[4:8] + " " + canonical[8:])
	got, err := Code(spaced, 1, cfg)
	if err != nil {
		t.Fatalf("Code(formatted): %v", err)
	}
	if got != want {
		t.Errorf("formatted secret produced %q, want %q", got, want)
	}
}

func TestGenerateSecretIsUsableAndUnique(t *testing.T) {
	cfg := DefaultConfig()
	seen := make(map[string]struct{}, 500)
	for i := 0; i < 500; i++ {
		secret, err := GenerateSecret()
		if err != nil {
			t.Fatalf("GenerateSecret: %v", err)
		}
		if _, dup := seen[secret]; dup {
			t.Fatal("duplicate secret generated")
		}
		seen[secret] = struct{}{}

		// Must decode and produce a code without error.
		code, err := Code(secret, StepFor(time.Now(), cfg), cfg)
		if err != nil {
			t.Fatalf("Code with generated secret: %v", err)
		}
		if len(code) != 6 {
			t.Errorf("code length = %d, want 6", len(code))
		}
	}
}

func TestConfigDefaultsAreApplied(t *testing.T) {
	// A zero Config must behave like DefaultConfig: an enrollment that stored no
	// parameters still has to validate against the interoperable defaults.
	var zero Config
	if err := zero.withDefaults().validate(); err != nil {
		t.Errorf("zero config invalid: %v", err)
	}
	want, err := Code(rfcSecretB32, 1, DefaultConfig())
	if err != nil {
		t.Fatalf("Code: %v", err)
	}
	got, err := Code(rfcSecretB32, 1, zero)
	if err != nil {
		t.Fatalf("Code(zero config): %v", err)
	}
	if got != want {
		t.Errorf("zero config produced %q, want %q", got, want)
	}
}

func TestConfigRejectsBadValues(t *testing.T) {
	cases := map[string]Config{
		"unknown algorithm": {Algorithm: "MD5", Digits: Digits6, Period: 30},
		"bad digits":        {Algorithm: AlgorithmSHA1, Digits: 7, Period: 30},
		"zero period":       {Algorithm: AlgorithmSHA1, Digits: Digits6, Period: 0},
		"negative skew":     {Algorithm: AlgorithmSHA1, Digits: Digits6, Period: 30, Skew: -1},
		"huge skew":         {Algorithm: AlgorithmSHA1, Digits: Digits6, Period: 30, Skew: 100},
		"long period":       {Algorithm: AlgorithmSHA1, Digits: Digits6, Period: 10000},
	}
	for label, cfg := range cases {
		t.Run(label, func(t *testing.T) {
			// Period 0 is filled in by withDefaults, so validate the raw config.
			if err := cfg.validate(); err == nil {
				t.Error("invalid config accepted")
			}
		})
	}
}

func TestProvisioningURIEscapesLabels(t *testing.T) {
	uri, err := ProvisioningURI("JAWAKER & Co", "user@example.com", rfcSecretB32, DefaultConfig())
	if err != nil {
		t.Fatalf("ProvisioningURI: %v", err)
	}
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Errorf("scheme = %q", uri)
	}
	// The ampersand in the issuer must be escaped; otherwise it would start a new
	// query parameter and silently drop the issuer (or inject one).
	if strings.Contains(uri, "JAWAKER & Co") {
		t.Errorf("unescaped issuer in %q", uri)
	}
	if !strings.Contains(uri, "JAWAKER%20%26%20Co") {
		t.Errorf("issuer not percent-encoded in %q", uri)
	}
	if !strings.Contains(uri, "secret="+rfcSecretB32) {
		t.Error("secret missing")
	}
	if !strings.Contains(uri, "algorithm=SHA1") || !strings.Contains(uri, "digits=6") || !strings.Contains(uri, "period=30") {
		t.Errorf("parameters missing in %q", uri)
	}

	// An account name containing a query separator must not be able to inject a
	// parameter, which is how a crafted enrollment could change the algorithm.
	evil, err := ProvisioningURI("Panel", "user@example.com&algorithm=MD5", rfcSecretB32, DefaultConfig())
	if err != nil {
		t.Fatalf("ProvisioningURI: %v", err)
	}
	if strings.Contains(evil, "&algorithm=MD5") {
		t.Errorf("account name injected a parameter: %q", evil)
	}
}

func TestProvisioningURIRequiresInputs(t *testing.T) {
	for _, tc := range []struct{ issuer, account string }{
		{"", "user@example.com"},
		{"  ", "user@example.com"},
		{"Panel", ""},
		{"Panel", "   "},
	} {
		if _, err := ProvisioningURI(tc.issuer, tc.account, rfcSecretB32, DefaultConfig()); err == nil {
			t.Errorf("issuer=%q account=%q accepted", tc.issuer, tc.account)
		}
	}
	if _, err := ProvisioningURI("Panel", "user@example.com", "!!!", DefaultConfig()); err == nil {
		t.Error("bad secret accepted")
	}
}

func TestStepForUsesPeriod(t *testing.T) {
	at := time.Unix(75, 0)
	if got := StepFor(at, Config{Period: 30}); got != 2 {
		t.Errorf("step = %d, want 2", got)
	}
	if got := StepFor(at, Config{Period: 60}); got != 1 {
		t.Errorf("step = %d, want 1", got)
	}
	// A zero period must fall back to the default rather than divide by zero.
	if got := StepFor(at, Config{}); got != 2 {
		t.Errorf("default-period step = %d, want 2", got)
	}
}
