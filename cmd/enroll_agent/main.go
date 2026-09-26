package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/bukansembarangkong/jawaker-panel/internal/config"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodes"
	"github.com/bukansembarangkong/jawaker-panel/internal/secret"
)

func main() {
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

	now := time.Now
	secrets, err := secret.New(secret.Options{DB: pool, Keys: cfg.SecretKeys})
	if err != nil {
		log.Fatalf("secrets: %v", err)
	}

	authority, _, err := nodes.EnsureAuthority(ctx, nodes.AuthorityOptions{
		DB:      pool,
		Secrets: secrets,
		Now:     now,
	})
	if err != nil {
		log.Fatalf("authority: %v", err)
	}

	store := nodes.NewStore(pool, now)

	// Clean up any stale tokens for "primary-node"
	_, _ = pool.Exec(ctx, "DELETE FROM enrollment_tokens WHERE node_name = 'primary-node'")

	_, tokenPlaintext, err := store.CreateToken(ctx, authority.ControllerID(), nodes.CreateTokenParams{
		NodeName: "primary-node",
	})
	if err != nil {
		log.Fatalf("CreateToken: %v", err)
	}

	fp := authority.ControllerFingerprint()
	fmt.Printf("TOKEN: %s\n", tokenPlaintext)
	fmt.Printf("CONTROLLER FP: %s\n", fp)

	stateDir := "/var/lib/jawaker-node"
	_ = os.RemoveAll(stateDir)
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		log.Fatalf("mkdir: %v", err)
	}

	// Run enrollment
	agentBin := "/usr/local/bin/jawaker-node-agent"
	cmd := exec.Command(agentBin, "enroll",
		"-controller", "http://localhost:8443",
		"-token", tokenPlaintext,
		"-fingerprint", fp,
		"-node-address", "127.0.0.1:7443",
		"-state-dir", stateDir,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("enroll: %v", err)
	}
	fmt.Println("=== ENROLLMENT SUCCESSFUL ===")

	// Now check the newly created server in DB and update its address if needed
	var srvID string
	err = pool.QueryRow(ctx, "SELECT id FROM servers WHERE name = 'Primary Node' ORDER BY created_at DESC LIMIT 1").Scan(&srvID)
	if err != nil {
		log.Printf("find server: %v", err)
	} else {
		// Set address to 127.0.0.1:7443
		_, err = pool.Exec(ctx, "UPDATE servers SET address = '127.0.0.1:7443' WHERE id = $1", srvID)
		if err != nil {
			log.Printf("update server address: %v", err)
		} else {
			fmt.Printf("Server %s address updated to 127.0.0.1:7443\n", srvID)
		}
		// Also update any sites that point to the old server ID
		res, err := pool.Exec(ctx, "UPDATE sites SET server_id = $1", srvID)
		if err != nil {
			log.Printf("update sites server_id: %v", err)
		} else {
			fmt.Printf("Updated %d sites to point to server %s\n", res.RowsAffected(), srvID)
		}
	}
	_ = strings.TrimSpace("")
}
