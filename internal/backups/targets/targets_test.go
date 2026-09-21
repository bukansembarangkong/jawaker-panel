package targets

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalRoundTripAndConfinement(t *testing.T) {
	dir := t.TempDir()
	l, newErr := NewLocal(LocalConfig{BaseDir: dir})
	if newErr != nil {
		t.Fatalf("new local: %v", newErr)
	}
	ctx := context.Background()

	if putErr := l.Put(ctx, "plans/nightly/run1.tar.gz", strings.NewReader("archive-bytes"), -1); putErr != nil {
		t.Fatalf("put: %v", putErr)
	}
	exists, existsErr := l.Exists(ctx, "plans/nightly/run1.tar.gz")
	if existsErr != nil || !exists {
		t.Fatalf("exists: %v %v", exists, existsErr)
	}

	rc, getErr := l.Get(ctx, "plans/nightly/run1.tar.gz")
	if getErr != nil {
		t.Fatalf("get: %v", getErr)
	}
	got, _ := io.ReadAll(rc)
	if closeErr := rc.Close(); closeErr != nil {
		t.Fatalf("close: %v", closeErr)
	}
	if string(got) != "archive-bytes" {
		t.Fatalf("get: got %q", got)
	}

	// Traversal is refused before any filesystem operation.
	for _, bad := range []string{"../outside.txt", "plans/../../etc/passwd"} {
		if badErr := l.Put(ctx, bad, strings.NewReader("x"), -1); badErr == nil {
			t.Errorf("key %q: traversal was not refused", bad)
		}
	}
	// And nothing landed outside the base dir.
	if _, statErr := os.Stat(filepath.Join(filepath.Dir(dir), "outside.txt")); !os.IsNotExist(statErr) {
		t.Error("traversal wrote a file outside base dir")
	}

	if delErr := l.Delete(ctx, "plans/nightly/run1.tar.gz"); delErr != nil {
		t.Fatalf("delete: %v", delErr)
	}
	exists, existsErr = l.Exists(ctx, "plans/nightly/run1.tar.gz")
	if existsErr != nil || exists {
		t.Fatalf("exists after delete: %v %v", exists, existsErr)
	}
	// Deleting an absent key is not an error.
	if delErr := l.Delete(ctx, "plans/nightly/run1.tar.gz"); delErr != nil {
		t.Fatalf("double delete: %v", delErr)
	}
	if _, misErr := l.Get(ctx, "plans/nightly/run1.tar.gz"); !errors.Is(misErr, ErrNotFound) {
		t.Fatalf("get missing: got %v, want ErrNotFound", misErr)
	}
}

func TestLocalRequiresBaseDir(t *testing.T) {
	if _, err := NewLocal(LocalConfig{}); err == nil {
		t.Fatal("empty base_dir was accepted")
	}
}

// TestS3SignatureMatchesIndependentComputation proves the Sig V4 implementation
// against a request captured by httptest: the test recomputes the signature
// from the captured headers and asserts equality. A broken canonical-request
// construction fails here, not in production.
func TestS3SignatureMatchesIndependentComputation(t *testing.T) {
	var captured *http.Request
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		captured = r.Clone(r.Context())
		captured.Header = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fixed := time.Date(2026, 9, 22, 3, 0, 0, 0, time.UTC)
	s3, err := NewS3(S3Config{
		Endpoint: srv.URL, Region: "us-east-1", Bucket: "jawaker-backups",
		AccessKey: "AKIATEST", SecretKey: "secret-test-key", Prefix: "proj1/",
	})
	if err != nil {
		t.Fatalf("new s3: %v", err)
	}
	s3.now = func() time.Time { return fixed }

	payload := []byte("backup-archive-content")
	if err := s3.Put(context.Background(), "run1.tar.gz", bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("put: %v", err)
	}
	if captured == nil {
		t.Fatal("server captured no request")
	}
	if string(body) != string(payload) {
		t.Fatalf("body: got %q", body)
	}
	if captured.URL.Path != "/jawaker-backups/proj1/run1.tar.gz" {
		t.Fatalf("path: got %s", captured.URL.Path)
	}

	// Recompute the signature independently and compare.
	auth := captured.Header.Get("Authorization")
	want := expectedSignature(t, captured, "secret-test-key", "us-east-1", fixed)
	if !strings.Contains(auth, "Signature="+want) {
		t.Fatalf("signature mismatch:\n got auth: %s\nwant sig:  %s", auth, want)
	}
	if !strings.Contains(auth, "Credential=AKIATEST/20260922/us-east-1/s3/aws4_request") {
		t.Fatalf("credential scope wrong: %s", auth)
	}
}

func TestS3GetNotFoundAndExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			http.NotFound(w, r)
		case http.MethodHead:
			if strings.HasSuffix(r.URL.Path, "present.tar.gz") {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	s3, err := NewS3(S3Config{
		Endpoint: srv.URL, Region: "auto", Bucket: "b",
		AccessKey: "k", SecretKey: "s",
	})
	if err != nil {
		t.Fatalf("new s3: %v", err)
	}
	ctx := context.Background()

	if _, getErr := s3.Get(ctx, "missing.tar.gz"); !errors.Is(getErr, ErrNotFound) {
		t.Fatalf("get missing: got %v, want ErrNotFound", getErr)
	}
	exists, existsErr := s3.Exists(ctx, "present.tar.gz")
	if existsErr != nil || !exists {
		t.Fatalf("exists present: %v %v", exists, existsErr)
	}
	exists, existsErr = s3.Exists(ctx, "absent.tar.gz")
	if existsErr != nil || exists {
		t.Fatalf("exists absent: %v %v", exists, existsErr)
	}
	if delErr := s3.Delete(ctx, "anything.tar.gz"); delErr != nil {
		t.Fatalf("delete: %v", delErr)
	}
}

func TestS3RejectsTraversalKeys(t *testing.T) {
	s3, err := NewS3(S3Config{
		Endpoint: "http://example.invalid", Region: "us-east-1", Bucket: "b",
		AccessKey: "k", SecretKey: "s",
	})
	if err != nil {
		t.Fatalf("new s3: %v", err)
	}
	for _, bad := range []string{"../escape", "/abs/key", "a/../../b"} {
		if badErr := s3.Put(context.Background(), bad, strings.NewReader("x"), 1); badErr == nil {
			t.Errorf("key %q was accepted", bad)
		}
	}
}

func TestBuildFactory(t *testing.T) {
	dir := t.TempDir()
	l, err := Build("local", []byte(`{"base_dir":"`+escapeJSON(dir)+`"}`))
	if err != nil {
		t.Fatalf("build local: %v", err)
	}
	if _, ok := l.(*Local); !ok {
		t.Fatalf("build local: got %T", l)
	}
	s3, err := Build("s3", []byte(`{"endpoint":"http://x","region":"r","bucket":"b","access_key":"k","secret_key":"s"}`))
	if err != nil {
		t.Fatalf("build s3: %v", err)
	}
	if _, ok := s3.(*S3); !ok {
		t.Fatalf("build s3: got %T", s3)
	}
	if _, err := Build("ftp", nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("build ftp: got %v, want ErrUnsupported", err)
	}
	if _, err := Build("s3", []byte(`{"endpoint":"http://x"}`)); err == nil {
		t.Fatal("incomplete s3 config was accepted")
	}
}

// expectedSignature recomputes the V4 signature from the captured request,
// independently of the code under test's request builder.
func expectedSignature(t *testing.T, r *http.Request, secret, region string, now time.Time) string {
	t.Helper()
	payloadHash := r.Header.Get("x-amz-content-sha256")
	amzDate := r.Header.Get("x-amz-date")
	canonical := strings.Join([]string{
		r.Method,
		r.URL.Path,
		"",
		"host:" + r.Host + "\n" +
			"x-amz-content-sha256:" + payloadHash + "\n" +
			"x-amz-date:" + amzDate + "\n",
		"host;x-amz-content-sha256;x-amz-date",
		payloadHash,
	}, "\n")
	dateStamp := now.UTC().Format("20060102")
	scope := dateStamp + "/" + region + "/s3/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonical)),
	}, "\n")
	sig := hmacSHA256(signingKey(secret, dateStamp, region), []byte(stringToSign))
	return hexEncode(sig)
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0x0f]
	}
	return string(out)
}

func escapeJSON(s string) string {
	return strings.ReplaceAll(s, `\`, `\\`)
}
