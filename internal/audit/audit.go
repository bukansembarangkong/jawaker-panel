// Package audit writes the append-only audit trail (SECURITY.md §16, API.md §6).
//
// Two rules shape this package:
//
//  1. The trail is written in the SAME transaction as the change it describes.
//     A privileged mutation that commits without its audit row is an
//     unexplained privileged mutation, so Record takes an executor (a pgx.Tx
//     or a pool) and callers pass their transaction.
//
//  2. A write failure is returned, never swallowed. Callers are expected to
//     abort the operation rather than perform an unaudited change.
//
// The database enforces the rest: migration 0004 makes audit_events reject
// UPDATE and DELETE outright, so even a buggy caller cannot rewrite history.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Actor types. Kept in sync with the audit_events CHECK constraint.
const (
	ActorUser     = "user"
	ActorAPIToken = "api_token"
	ActorService  = "service"
	ActorSystem   = "system"
	ActorAI       = "ai"
)

// Results. Kept in sync with the audit_events CHECK constraint.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
	ResultDenied  = "denied"
)

// Execer is the minimal database surface Record needs. Both pgx.Tx and
// *pgxpool.Pool satisfy it, so the same call works inside or outside a
// transaction without a wrapper type.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Event is one audit record.
//
// It deliberately has no field for secret material: context carries
// references (secret://...) and identifiers only (SECURITY.md §8).
type Event struct {
	// ActorType is one of ActorUser, ActorAPIToken, ActorService, ActorSystem,
	// ActorAI. Required.
	ActorType string
	// ActorID identifies the acting user/service. Empty for system events.
	ActorID string
	// ImpersonatorID is set when a privileged user acts on behalf of another.
	ImpersonatorID string
	// Action is the canonical key, e.g. "site.create", "session.revoke".
	// Required.
	Action string
	// ResourceType names the changed resource kind. Required.
	ResourceType string
	// ResourceID is the concrete resource identifier, when there is one.
	ResourceID string
	// RequestID correlates this event with logs, jobs, and the HTTP response.
	RequestID string
	// JobID and RevisionID correlate with the job engine and revision history.
	JobID      string
	RevisionID string
	// Result is one of ResultSuccess, ResultFailure, ResultDenied. Required.
	Result string
	// ErrorCode is the stable machine code for a failure (matches apierr).
	ErrorCode string
	// Reason is a safe human explanation. Required for denials and for
	// impersonated actions, because "who let this happen and why" is exactly
	// what an investigator needs and cannot reconstruct later.
	Reason string
	// Context carries non-secret structured detail. Serialized as jsonb.
	Context map[string]any
	// SourceIP is the client address, without a port. Empty when unknown.
	SourceIP string
	// UserAgent is the client's declared user agent.
	UserAgent string
}

// insertAuditEvent uses explicit casts for the uuid, jsonb, and inet columns so
// the parameter types are unambiguous: pgx is handed text and PostgreSQL does
// the conversion, which keeps empty-string → NULL handling in one place.
const insertAuditEvent = `
INSERT INTO audit_events (
    actor_type, actor_id, impersonator_id, action, resource_type, resource_id,
    request_id, job_id, revision_id, result, error_code, reason, context,
    source_ip, user_agent
) VALUES (
    $1, NULLIF($2, '')::uuid, NULLIF($3, '')::uuid, $4, $5, NULLIF($6, ''),
    NULLIF($7, ''), NULLIF($8, '')::uuid, NULLIF($9, '')::uuid, $10,
    NULLIF($11, ''), NULLIF($12, ''), $13::jsonb,
    NULLIF($14, '')::inet, NULLIF($15, '')
)`

// Record appends one event. It validates the closed vocabularies before
// touching the database so a typo in a call site names the offending field
// instead of surfacing as an opaque constraint violation.
func Record(ctx context.Context, db Execer, e Event) error {
	if err := e.validate(); err != nil {
		return err
	}
	if db == nil {
		return errors.New("audit: executor is required")
	}

	contextJSON := []byte("{}")
	if len(e.Context) > 0 {
		encoded, err := json.Marshal(e.Context)
		if err != nil {
			return fmt.Errorf("audit: encode context: %w", err)
		}
		contextJSON = encoded
	}

	// SourceIP must be a bare address (no port) for the inet column.
	// Callers frequently pass r.RemoteAddr which is "host:port" or "[::1]:port".
	if e.SourceIP != "" {
		if host, _, err := net.SplitHostPort(e.SourceIP); err == nil {
			e.SourceIP = host
		}
	}

	if _, err := db.Exec(ctx, insertAuditEvent,
		e.ActorType,
		e.ActorID,
		e.ImpersonatorID,
		e.Action,
		e.ResourceType,
		e.ResourceID,
		e.RequestID,
		e.JobID,
		e.RevisionID,
		e.Result,
		e.ErrorCode,
		e.Reason,
		string(contextJSON),
		e.SourceIP,
		e.UserAgent,
	); err != nil {
		return fmt.Errorf("audit: record %s: %w", e.Action, err)
	}
	return nil
}

// validate enforces the invariants the database also enforces, but with errors
// that name the field. The database remains the authority; this only makes
// programming mistakes cheap to find.
func (e Event) validate() error {
	var errs []error

	switch e.ActorType {
	case ActorUser, ActorAPIToken, ActorService, ActorSystem, ActorAI:
	default:
		errs = append(errs, fmt.Errorf("actor_type %q is not one of user|api_token|service|system|ai", e.ActorType))
	}

	switch e.Result {
	case ResultSuccess, ResultFailure, ResultDenied:
	default:
		errs = append(errs, fmt.Errorf("result %q is not one of success|failure|denied", e.Result))
	}

	if strings.TrimSpace(e.Action) == "" {
		errs = append(errs, errors.New("action is required"))
	}
	if strings.TrimSpace(e.ResourceType) == "" {
		errs = append(errs, errors.New("resource_type is required"))
	}

	// A denial without a reason cannot be reviewed later, and an impersonated
	// action without a reason is indistinguishable from an account takeover.
	if e.Result == ResultDenied && strings.TrimSpace(e.Reason) == "" {
		errs = append(errs, errors.New("reason is required for denied events"))
	}
	if e.ImpersonatorID != "" && strings.TrimSpace(e.Reason) == "" {
		errs = append(errs, errors.New("reason is required for impersonated actions"))
	}

	return errors.Join(errs...)
}

// Compile-time proof that the executor contract holds for the types callers
// actually pass, so a signature drift is caught at build time.
var (
	_ Execer = (pgx.Tx)(nil)
)
