package nodeagent

// database_stubs.go contains placeholder implementations for the Phase 5
// database operations. These stubs allow the dispatch switch in server.go and
// the drift test (TestDispatchHandlesEveryServedOperation) to stay in sync with
// the nodewire registry while real executors are delivered in PR-C.
//
// Each stub returns CodeUnsupportedOperation until the Executors struct gains
// the capability detection fields that indicate a working database engine is
// present. PR-C will delete this file and replace with real implementations.
//
// ponytail: stubs → real executors with unix-socket admin calls; add when
// Executors.hasPg / Executors.hasMariaDB detection lands in PR-C.

import (
	"context"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// dbUnsupported is the shared refusal for database operations on a node that
// has not reported the relevant database capability.
func dbUnsupported(engine string) error {
	return &nodewire.Error{
		Code:    nodewire.CodeUnsupportedOperation,
		Message: "database operations are not yet available on this node (engine: " + engine + ")",
	}
}

// ManageDatabase is a stub; PR-C provides the real implementation.
func (e *Executors) ManageDatabase(_ context.Context, in nodewire.DatabaseManageInput) (nodewire.DatabaseManageResult, error) {
	return nodewire.DatabaseManageResult{}, dbUnsupported(in.Engine)
}

// DumpDatabase is a stub; PR-C provides the real implementation.
func (e *Executors) DumpDatabase(_ context.Context, in nodewire.DatabaseDumpInput) (nodewire.DatabaseDumpResult, error) {
	return nodewire.DatabaseDumpResult{}, dbUnsupported(in.Engine)
}

// RestoreDatabase is a stub; PR-C provides the real implementation.
func (e *Executors) RestoreDatabase(_ context.Context, in nodewire.DatabaseRestoreInput) (nodewire.DatabaseRestoreResult, error) {
	return nodewire.DatabaseRestoreResult{}, dbUnsupported(in.Engine)
}

// GetDatabaseMetrics is a stub; PR-C provides the real implementation.
func (e *Executors) GetDatabaseMetrics(_ context.Context, in nodewire.DatabaseMetricsInput) (nodewire.DatabaseMetricsResult, error) {
	return nodewire.DatabaseMetricsResult{}, dbUnsupported(in.Engine)
}

// UpgradeDatabase is a stub; PR-C provides the real implementation.
func (e *Executors) UpgradeDatabase(_ context.Context, in nodewire.DatabaseUpgradeInput) (nodewire.DatabaseUpgradeResult, error) {
	return nodewire.DatabaseUpgradeResult{}, dbUnsupported(in.Engine)
}
