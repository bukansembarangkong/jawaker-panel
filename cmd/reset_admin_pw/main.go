package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/bukansembarangkong/jawaker-panel/internal/config"
	"github.com/bukansembarangkong/jawaker-panel/internal/password"
)

func main() {
	newPass := os.Getenv("NEW_PASSWORD")
	if newPass == "" {
		newPass = "AdminJawaker123!"
	}

	ctx := context.Background()
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	hash, err := password.Hash(newPass, password.DefaultParams())
	if err != nil {
		log.Fatalf("hash: %v", err)
	}

	// Mark old credential superseded
	_, err = pool.Exec(ctx,
		"UPDATE password_credentials SET superseded_at = $1 WHERE user_id = (SELECT id FROM users WHERE is_owner = true) AND superseded_at IS NULL",
		time.Now())
	if err != nil {
		log.Fatalf("supersede: %v", err)
	}

	// Insert new credential
	_, err = pool.Exec(ctx,
		"INSERT INTO password_credentials (user_id, password_hash) VALUES ((SELECT id FROM users WHERE is_owner = true), $1)",
		hash)
	if err != nil {
		log.Fatalf("insert: %v", err)
	}

	fmt.Printf("Password reset OK. New password: %s\n", newPass)
}
