package apierr

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestMarshalEnvelopeShape(t *testing.T) {
	e := InvalidRequest("domain is required", map[string]any{"field": "domain"}).
		WithRequestID("req_test123")

	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["request_id"] != "req_test123" {
		t.Errorf("request_id = %v, want req_test123", body["request_id"])
	}
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("error field missing or not an object: %v", body)
	}
	if errObj["code"] != CodeInvalidRequest {
		t.Errorf("code = %v, want %v", errObj["code"], CodeInvalidRequest)
	}
	if errObj["retryable"] != false {
		t.Errorf("retryable = %v, want false", errObj["retryable"])
	}
	details, _ := errObj["details"].(map[string]any)
	if details["field"] != "domain" {
		t.Errorf("details.field = %v, want domain", details["field"])
	}
}

func TestMarshalNeverLeaksInternalCause(t *testing.T) {
	e := Internal(errors.New("pq: connection refused with password=hunter2")).
		WithRequestID("req_x")

	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(raw)
	if strings.Contains(s, "hunter2") || strings.Contains(s, "pq:") {
		t.Errorf("internal cause leaked into JSON: %s", s)
	}
	if !strings.Contains(s, `"code":"internal_error"`) {
		t.Errorf("expected stable internal code in JSON: %s", s)
	}
}

func TestWithRequestIDDoesNotMutateOriginal(t *testing.T) {
	e := NotFound("missing")
	clone := e.WithRequestID("req_1")
	other := e.WithRequestID("req_2")

	rawClone, _ := json.Marshal(clone)
	rawOther, _ := json.Marshal(other)
	if !strings.Contains(string(rawClone), "req_1") || strings.Contains(string(rawClone), "req_2") {
		t.Errorf("clone request id wrong: %s", rawClone)
	}
	if !strings.Contains(string(rawOther), "req_2") {
		t.Errorf("other request id wrong: %s", rawOther)
	}
}

func TestFromErrorCoercesUnknownErrors(t *testing.T) {
	plain := errors.New("boom")
	got := FromError(plain)
	if got.Code != CodeInternal {
		t.Errorf("FromError(plain).Code = %q, want %q", got.Code, CodeInternal)
	}
	if !errors.Is(got, plain) {
		t.Error("FromError should preserve the cause chain via errors.Is")
	}

	orig := Forbidden("nope")
	if FromError(orig) != orig {
		t.Error("FromError should pass through *Error values unchanged")
	}
}

func TestFromErrorUnwrapsNested(t *testing.T) {
	wrapped := errors.Join(errors.New("context"), Forbidden("denied"))
	got := FromError(wrapped)
	if got.Code != CodeForbidden {
		t.Errorf("FromError(wrapped).Code = %q, want %q", got.Code, CodeForbidden)
	}
}

func TestStatusCodes(t *testing.T) {
	cases := []struct {
		err    *Error
		status int
	}{
		{InvalidRequest("x", nil), 400},
		{Unauthorized(""), 401},
		{Forbidden(""), 403},
		{NotFound(""), 404},
		{Conflict("x", nil), 409},
		{PayloadTooLarge(""), 413},
		{Internal(nil), 500},
		{ServiceUnavailable("x"), 503},
		{DatabaseUnavailable(), 503},
	}
	for _, c := range cases {
		if c.err.Status != c.status {
			t.Errorf("%s: Status = %d, want %d", c.err.Code, c.err.Status, c.status)
		}
	}
}

func TestDatabaseUnavailableIsRetryable(t *testing.T) {
	e := DatabaseUnavailable()
	if !e.Retryable {
		t.Error("database_unavailable should be retryable")
	}
}
