// Package revisions: GitHub REST API GitOps syncer (PRD §24).
//
// Pushes declarative candidate state for each revision directly to a GitHub repository
// using the GitHub REST Contents API without requiring local git CLI or third-party SDKs.
// Zero new external dependencies: uses stdlib net/http and encoding/json only.
package revisions

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GitHubSyncConfig holds the parameters needed to push to a GitHub repository.
type GitHubSyncConfig struct {
	// Token is a personal access token or GitHub App installation token.
	Token string
	// RepoURL is the target repo, e.g. "owner/repo" or "https://github.com/owner/repo".
	RepoURL string
	// Branch is the target branch (defaults to "main").
	Branch string
}

// GitHubSyncer implements the Syncer interface by committing revisions via GitHub REST API.
type GitHubSyncer struct {
	owner  string
	repo   string
	token  string
	branch string
	client *http.Client
}

// NewGitHubSyncer creates a new GitHub-backed GitOps syncer.
// Returns nil if config is incomplete (token or repo empty).
func NewGitHubSyncer(cfg GitHubSyncConfig) *GitHubSyncer {
	if cfg.Token == "" || cfg.RepoURL == "" {
		return nil
	}

	owner, repo := parseGitHubRepo(cfg.RepoURL)
	if owner == "" || repo == "" {
		return nil
	}

	branch := cfg.Branch
	if branch == "" {
		branch = "main"
	}

	return &GitHubSyncer{
		owner:  owner,
		repo:   repo,
		token:  cfg.Token,
		branch: branch,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func parseGitHubRepo(raw string) (owner, repo string) {
	s := strings.TrimPrefix(raw, "https://github.com/")
	s = strings.TrimPrefix(s, "http://github.com/")
	s = strings.TrimSuffix(s, ".git")
	s = strings.Trim(s, "/")
	parts := strings.Split(s, "/")
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	return "", ""
}

// ghContentsRequest is the GitHub API payload for creating/updating a file.
type ghContentsRequest struct {
	Message string `json:"message"`
	Content string `json:"content"` // base64-encoded
	Branch  string `json:"branch"`
	SHA     string `json:"sha,omitempty"` // existing file SHA for updates
}

type ghContentsResponse struct {
	Commit struct {
		SHA string `json:"sha"`
	} `json:"commit"`
	Message string `json:"message,omitempty"`
}

type ghGetContentResponse struct {
	SHA string `json:"sha"`
}

// SyncRevision commits the candidate document to revisions/{resource_type}/{resource_id}.json.
func (s *GitHubSyncer) SyncRevision(ctx context.Context, rev Revision) (string, error) {
	path := fmt.Sprintf("revisions/%s/%s.json", rev.ResourceType, rev.ResourceID)

	contentJSON, err := json.MarshalIndent(rev.Candidate, "", "  ")
	if err != nil {
		return "", fmt.Errorf("github sync: marshal candidate: %w", err)
	}

	b64Content := base64.StdEncoding.EncodeToString(contentJSON)
	commitMsg := fmt.Sprintf("chore(%s): update %s revision %s [skip ci]", rev.ResourceType, rev.ResourceID, rev.ID[:8])

	// Check if file already exists to obtain its blob SHA (required for PUT /contents)
	existingSHA := s.getFileSHA(ctx, path)

	reqBody := ghContentsRequest{
		Message: commitMsg,
		Content: b64Content,
		Branch:  s.branch,
		SHA:     existingSHA,
	}

	bodyBytes, _ := json.Marshal(reqBody)
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", s.owner, s.repo, path)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("github sync: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "jawaker-gitops")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("github sync: do request: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	var out ghContentsResponse
	_ = json.Unmarshal(raw, &out)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github sync: api returned %d: %s", resp.StatusCode, out.Message)
	}

	return out.Commit.SHA, nil
}

func (s *GitHubSyncer) getFileSHA(ctx context.Context, path string) string {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s?ref=%s", s.owner, s.repo, path, s.branch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "jawaker-gitops")

	resp, err := s.client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	defer resp.Body.Close()

	var out ghGetContentResponse
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	_ = json.Unmarshal(raw, &out)
	return out.SHA
}
