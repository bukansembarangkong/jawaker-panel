// Package apitoken implements personal and service API tokens per PRD §26.2.
package apitoken

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound = errors.New("apitoken: token not found")
	ErrRevoked  = errors.New("apitoken: token revoked")
	ErrExpired  = errors.New("apitoken: token expired")
)

type Token struct {
	ID           string     `json:"id"`
	UserID       string     `json:"user_id"`
	Name         string     `json:"name"`
	Kind         string     `json:"kind"`
	TokenPrefix  string     `json:"token_prefix"`
	Scopes       []string   `json:"scopes"`
	AllowedCIDRs []string   `json:"allowed_cidrs"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

type CreatedToken struct {
	Token
	Plaintext string `json:"plaintext"`
}

type Store struct {
	db  *pgxpool.Pool
	now func() time.Time
}

func NewStore(db *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{db: db, now: now}
}

// GeneratePlaintext generates a secure random token with prefix "jwk_".
func GeneratePlaintext() (string, []byte, string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, "", err
	}
	plaintext := "jwk_" + hex.EncodeToString(buf)
	hash := sha256.Sum256([]byte(plaintext))
	prefix := plaintext[:8]
	return plaintext, hash[:], prefix, nil
}

// Create inserts a new token, returning the plaintext string exactly once.
func (s *Store) Create(ctx context.Context, userID, name, kind string, scopes, cidrs []string, expiresAt *time.Time) (*CreatedToken, error) {
	plaintext, hash, prefix, err := GeneratePlaintext()
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	var t Token
	t.UserID = userID
	t.Name = name
	t.Kind = kind
	t.TokenPrefix = prefix
	t.Scopes = scopes
	t.AllowedCIDRs = cidrs
	t.ExpiresAt = expiresAt
	t.CreatedAt = s.now()

	row := s.db.QueryRow(ctx, `
		INSERT INTO api_tokens (user_id, name, kind, token_hash, token_prefix, scopes, allowed_cidrs, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id
	`, userID, name, kind, hash, prefix, scopes, cidrs, expiresAt, t.CreatedAt)

	if err := row.Scan(&t.ID); err != nil {
		return nil, fmt.Errorf("insert token: %w", err)
	}

	return &CreatedToken{
		Token:     t,
		Plaintext: plaintext,
	}, nil
}

// ListByUser lists active and revoked tokens for a user.
func (s *Store) ListByUser(ctx context.Context, userID string) ([]Token, error) {
	rows, err := s.db.Query(ctx, `
		SELECT id, user_id, name, kind, token_prefix, scopes, allowed_cidrs, expires_at, revoked_at, last_used_at, created_at
		FROM api_tokens
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Token
	for rows.Next() {
		var t Token
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.Kind, &t.TokenPrefix, &t.Scopes, &t.AllowedCIDRs, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Revoke revokes a token immediately.
func (s *Store) Revoke(ctx context.Context, userID, tokenID string) error {
	now := s.now()
	res, err := s.db.Exec(ctx, `
		UPDATE api_tokens
		SET revoked_at = $1
		WHERE id = $2 AND user_id = $3 AND revoked_at IS NULL
	`, now, tokenID, userID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Authenticate resolves a raw plaintext bearer token into a Token object.
func (s *Store) Authenticate(ctx context.Context, raw string) (*Token, error) {
	hash := sha256.Sum256([]byte(raw))
	var t Token
	row := s.db.QueryRow(ctx, `
		SELECT id, user_id, name, kind, token_prefix, scopes, allowed_cidrs, expires_at, revoked_at, last_used_at, created_at
		FROM api_tokens
		WHERE token_hash = $1
	`, hash[:])

	if err := row.Scan(&t.ID, &t.UserID, &t.Name, &t.Kind, &t.TokenPrefix, &t.Scopes, &t.AllowedCIDRs, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt, &t.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if t.RevokedAt != nil {
		return nil, ErrRevoked
	}
	now := s.now()
	if t.ExpiresAt != nil && now.After(*t.ExpiresAt) {
		return nil, ErrExpired
	}

	// Update last_used_at asynchronously
	go func(id string, used time.Time) {
		_, _ = s.db.Exec(context.Background(), `UPDATE api_tokens SET last_used_at = $1 WHERE id = $2`, used, id)
	}(t.ID, now)

	return &t, nil
}
