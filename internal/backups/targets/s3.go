package targets

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// S3Config configures an S3-compatible destination. One shape covers AWS S3,
// Cloudflare R2, Backblaze B2, and MinIO — they all speak the same API.
type S3Config struct {
	// Endpoint is the base URL, e.g. "https://s3.amazonaws.com" or
	// "https://<account>.r2.cloudflarestorage.com". Required.
	Endpoint string `json:"endpoint"`
	// Region is the signing region, e.g. "us-east-1" ("auto" for R2). Required.
	Region string `json:"region"`
	// Bucket is the destination bucket. Required.
	Bucket string `json:"bucket"`
	// AccessKey and SecretKey are the credentials. Required.
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	// Prefix is prepended to every key (optional).
	Prefix string `json:"prefix"`
}

// S3 is an S3-compatible object storage target. Signing is AWS Signature V4
// implemented with stdlib crypto/hmac — no SDK.
type S3 struct {
	cfg    S3Config
	client *http.Client
	// now is overridable in tests so signatures are reproducible.
	now func() time.Time
}

// NewS3 validates the config and returns an S3 target.
func NewS3(cfg S3Config) (*S3, error) {
	var errs []error
	if cfg.Endpoint == "" {
		errs = append(errs, errors.New("endpoint is required"))
	}
	if cfg.Region == "" {
		errs = append(errs, errors.New("region is required"))
	}
	if cfg.Bucket == "" {
		errs = append(errs, errors.New("bucket is required"))
	}
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		errs = append(errs, errors.New("access_key and secret_key are required"))
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("targets: s3 config: %w", errors.Join(errs...))
	}
	return &S3{cfg: cfg, client: http.DefaultClient, now: time.Now}, nil
}

func (s *S3) objectKey(key string) (string, error) {
	if key == "" {
		return "", errors.New("targets: key is required")
	}
	// Reject traversal and absolute keys; the prefix is operator-controlled
	// config, the key comes from callers.
	if strings.Contains(key, "..") || strings.HasPrefix(key, "/") {
		return "", fmt.Errorf("targets: key %q is not a relative path", key)
	}
	return s.cfg.Prefix + key, nil
}

// Put uploads the object.
func (s *S3) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	full, err := s.objectKey(key)
	if err != nil {
		return err
	}
	resp, err := s.do(ctx, http.MethodPut, full, r, size)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("targets: s3 put %s: status %d: %s", full, resp.StatusCode, body)
	}
	return nil
}

// Get downloads the object.
func (s *S3) Get(ctx context.Context, key string) (io.ReadCloser, error) {
	full, err := s.objectKey(key)
	if err != nil {
		return nil, err
	}
	resp, err := s.do(ctx, http.MethodGet, full, nil, 0)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("targets: %w: %s", ErrNotFound, key)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		return nil, fmt.Errorf("targets: s3 get %s: status %d: %s", full, resp.StatusCode, body)
	}
	return resp.Body, nil
}

// Exists reports object presence via HEAD.
func (s *S3) Exists(ctx context.Context, key string) (bool, error) {
	full, err := s.objectKey(key)
	if err != nil {
		return false, err
	}
	resp, err := s.do(ctx, http.MethodHead, full, nil, 0)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("targets: s3 head %s: status %d", full, resp.StatusCode)
	}
}

// Delete removes the object. S3 answers 204 even for absent keys.
func (s *S3) Delete(ctx context.Context, key string) error {
	full, err := s.objectKey(key)
	if err != nil {
		return err
	}
	resp, err := s.do(ctx, http.MethodDelete, full, nil, 0)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("targets: s3 delete %s: status %d: %s", full, resp.StatusCode, body)
	}
	return nil
}

// do signs and performs one request against the bucket.
func (s *S3) do(ctx context.Context, method, key string, body io.Reader, size int64) (*http.Response, error) {
	endpoint, err := url.Parse(s.cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("targets: parse endpoint: %w", err)
	}
	// Path-style addressing: /{bucket}/{key}. Works for every S3-compatible
	// provider, unlike virtual-host style which needs per-provider DNS.
	objectPath := "/" + s.cfg.Bucket + "/" + escapePath(key)

	// Hash the body for the signature. The body is read fully into memory
	// here; backup archives are streamed per-object and bounded by the plan's
	// size policy. ponytail: for multi-GB archives, switch to chunked signing
	// (aws-chunked content encoding) — adds complexity only when needed.
	var payload []byte
	if body != nil {
		payload, err = io.ReadAll(body)
		if err != nil {
			return nil, fmt.Errorf("targets: read body: %w", err)
		}
	}
	payloadHash := sha256Hex(payload)

	now := s.now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	host := endpoint.Host
	req, err := http.NewRequestWithContext(ctx, method, endpoint.Scheme+"://"+host+objectPath, strings.NewReader(string(payload)))
	if err != nil {
		return nil, fmt.Errorf("targets: build request: %w", err)
	}
	if size >= 0 && body != nil {
		req.ContentLength = int64(len(payload))
	}
	req.Header.Set("Host", host)
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)

	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	canonical := strings.Join([]string{
		method,
		objectPath,
		"", // no query string
		"host:" + host + "\n" +
			"x-amz-content-sha256:" + payloadHash + "\n" +
			"x-amz-date:" + amzDate + "\n",
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := dateStamp + "/" + s.cfg.Region + "/s3/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonical)),
	}, "\n")

	signature := hex.EncodeToString(hmacSHA256(signingKey(s.cfg.SecretKey, dateStamp, s.cfg.Region), []byte(stringToSign)))
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		s.cfg.AccessKey, scope, signedHeaders, signature))

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("targets: s3 request: %w", err)
	}
	return resp, nil
}

// signingKey derives the V4 signing key: kSecret -> kDate -> kRegion -> kService -> kSigning.
func signingKey(secret, dateStamp, region string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// escapePath percent-encodes a key for the canonical URI, keeping slashes.
func escapePath(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}
