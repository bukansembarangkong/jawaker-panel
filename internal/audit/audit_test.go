package audit

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// fakeExecer records the arguments Record passes, so the statement shape and
// argument ordering are pinned without a database. Ordering matters: a
// transposed argument would silently write the wrong actor or action.
type fakeExecer struct {
	gotSQL  string
	gotArgs []any
	err     error
}

func (f *fakeExecer) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.gotSQL = sql
	f.gotArgs = args
	return pgconn.CommandTag{}, f.err
}

func validEvent() Event {
	return Event{
		ActorType:    ActorUser,
		ActorID:      "11111111-1111-1111-1111-111111111111",
		Action:       "site.create",
		ResourceType: "site",
		ResourceID:   "site-1",
		RequestID:    "req_abc",
		Result:       ResultSuccess,
	}
}

func TestRecordWritesExpectedColumnsInOrder(t *testing.T) {
	db := &fakeExecer{}
	if err := Record(context.Background(), db, validEvent()); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if !strings.Contains(db.gotSQL, "INSERT INTO audit_events") {
		t.Errorf("SQL does not target audit_events: %q", db.gotSQL)
	}

	want := []any{
		ActorUser,
		"11111111-1111-1111-1111-111111111111",
		"", // impersonator
		"site.create",
		"site",
		"site-1",
		"req_abc",
		"", // job
		"", // revision
		ResultSuccess,
		"",   // error code
		"",   // reason
		"{}", // context
		"",   // source ip
		"",   // user agent
	}
	if len(db.gotArgs) != len(want) {
		t.Fatalf("got %d args, want %d", len(db.gotArgs), len(want))
	}
	for i := range want {
		if db.gotArgs[i] != want[i] {
			t.Errorf("arg %d = %#v, want %#v", i, db.gotArgs[i], want[i])
		}
	}
}

// An empty-string convention maps to SQL NULL via NULLIF, so "not set" is
// never stored as a zero uuid or an empty inet.
func TestRecordUsesNullForUnsetFields(t *testing.T) {
	db := &fakeExecer{}
	if err := Record(context.Background(), db, validEvent()); err != nil {
		t.Fatalf("Record: %v", err)
	}
	for _, fragment := range []string{
		"NULLIF($2, '')",        // actor_id
		"NULLIF($3, '')",        // impersonator_id
		"NULLIF($7, '')",        // request_id
		"$13::jsonb",            // context
		"NULLIF($14, '')::inet", // source_ip
	} {
		if !strings.Contains(db.gotSQL, fragment) {
			t.Errorf("SQL lacks expected fragment %q", fragment)
		}
	}
}

func TestRecordSerializesContext(t *testing.T) {
	db := &fakeExecer{}
	e := validEvent()
	e.Context = map[string]any{"site_id": "site-1", "attempt": 2}
	if err := Record(context.Background(), db, e); err != nil {
		t.Fatalf("Record: %v", err)
	}
	got, ok := db.gotArgs[12].(string)
	if !ok {
		t.Fatalf("context arg = %#v, want string", db.gotArgs[12])
	}
	if !strings.Contains(got, `"site_id":"site-1"`) || !strings.Contains(got, `"attempt":2`) {
		t.Errorf("context json = %q", got)
	}
}

func TestRecordRejectsUnknownActorAndResult(t *testing.T) {
	cases := map[string]func(*Event){
		"unknown actor":  func(e *Event) { e.ActorType = "ghost" },
		"empty actor":    func(e *Event) { e.ActorType = "" },
		"unknown result": func(e *Event) { e.Result = "maybe" },
		"empty result":   func(e *Event) { e.Result = "" },
	}
	for label, mutate := range cases {
		t.Run(label, func(t *testing.T) {
			db := &fakeExecer{}
			e := validEvent()
			mutate(&e)
			if err := Record(context.Background(), db, e); err == nil {
				t.Fatal("invalid event accepted")
			}
			// Validation must happen before the write, so nothing was sent.
			if db.gotSQL != "" {
				t.Error("invalid event reached the database")
			}
		})
	}
}

func TestRecordRequiresActionAndResourceType(t *testing.T) {
	for _, mutate := range []func(*Event){
		func(e *Event) { e.Action = "" },
		func(e *Event) { e.Action = "   " },
		func(e *Event) { e.ResourceType = "" },
	} {
		db := &fakeExecer{}
		e := validEvent()
		mutate(&e)
		if err := Record(context.Background(), db, e); err == nil {
			t.Fatal("incomplete event accepted")
		}
	}
}

// An unexplained denial cannot be reviewed later, and an unexplained
// impersonated action is indistinguishable from an account takeover.
func TestRecordRequiresReasonForDenialsAndImpersonation(t *testing.T) {
	db := &fakeExecer{}
	denied := validEvent()
	denied.Result = ResultDenied
	if err := Record(context.Background(), db, denied); err == nil {
		t.Fatal("denied event without a reason accepted")
	}

	impersonated := validEvent()
	impersonated.ImpersonatorID = "22222222-2222-2222-2222-222222222222"
	if err := Record(context.Background(), db, impersonated); err == nil {
		t.Fatal("impersonated event without a reason accepted")
	}

	// With a reason, both are fine.
	denied.Reason = "permission denied: no matching grant"
	if err := Record(context.Background(), db, denied); err != nil {
		t.Errorf("denied event with reason rejected: %v", err)
	}
	impersonated.Reason = "support investigation #4711"
	if err := Record(context.Background(), db, impersonated); err != nil {
		t.Errorf("impersonated event with reason rejected: %v", err)
	}
}

func TestRecordPropagatesDatabaseError(t *testing.T) {
	boom := errors.New("connection reset")
	db := &fakeExecer{err: boom}
	err := Record(context.Background(), db, validEvent())
	if err == nil {
		t.Fatal("database error swallowed")
	}
	// The cause must remain inspectable so the caller can decide to abort.
	if !errors.Is(err, boom) {
		t.Errorf("error %v does not wrap the cause", err)
	}
}

func TestRecordRequiresExecutor(t *testing.T) {
	if err := Record(context.Background(), nil, validEvent()); err == nil {
		t.Fatal("nil executor accepted")
	}
}
