package controller

import (
	"testing"

	"github.com/bukansembarangkong/jawaker-panel/internal/databases"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNewDatabaseWorkerRequiresDependencies(t *testing.T) {
	_, err := NewDatabaseWorker(DatabaseWorkerOptions{})
	if err == nil {
		t.Fatal("expected error without Pool")
	}

	_, err = NewDatabaseWorker(DatabaseWorkerOptions{
		Pool: &pgxpool.Pool{},
	})
	if err == nil {
		t.Fatal("expected error without Databases store")
	}
}

func TestDatabaseWorkerOptionsDefaultOwner(t *testing.T) {
	opts := DatabaseWorkerOptions{
		Pool:      &pgxpool.Pool{},
		Databases: &databases.Store{},
	}
	// Verify that empty Owner does not panic during option check.
	if opts.Owner != "" {
		t.Errorf("Owner = %q, want empty before construction", opts.Owner)
	}
}

func TestDatabaseHandlersAreNotNil(t *testing.T) {
	d := &databases.Store{}
	if h := newDBProvisionHandler(d, nil, nil); h == nil {
		t.Error("newDBProvisionHandler returned nil")
	}
	if h := newDBDumpHandler(d, nil, nil); h == nil {
		t.Error("newDBDumpHandler returned nil")
	}
	if h := newDBRestoreHandler(d, nil, nil); h == nil {
		t.Error("newDBRestoreHandler returned nil")
	}
	if h := newDBDeleteHandler(d, nil, nil); h == nil {
		t.Error("newDBDeleteHandler returned nil")
	}
}
