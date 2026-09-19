// Package apierr defines the canonical API error shape (API.md §8).
//
// Every client-visible error carries a stable machine code, a safe human
// message, retryability, non-secret details, and the request correlation ID.
// Internal error causes are logged server-side but never serialized to
// clients unless explicitly marked safe.
package apierr

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Stable machine-readable error codes. Clients may branch on these; they must
// not change meaning once released.
const (
	CodeInvalidRequest     = "invalid_request"
	CodeUnauthorized       = "unauthorized"
	CodeForbidden          = "forbidden"
	CodeNotFound           = "not_found"
	CodeConflict           = "conflict"
	CodePayloadTooLarge    = "payload_too_large"
	CodeInternal           = "internal_error"
	CodeServiceUnavailable = "service_unavailable"
	CodeDatabaseUnavailable = "database_unavailable"
)

// Error is an API error with a stable code and HTTP status mapping.
type Error struct {
	// Code is the stable machine-readable identifier.
	Code string `json:"code"`
	// Message is safe for end users. Never contains secrets or stack traces.
	Message string `json:"message"`
	// Retryable hints whether the identical request may succeed later.
	Retryable bool `json:"retryable"`
	// Details carries schema-specific, non-secret context. May be nil.
	Details map[string]any `json:"details,omitempty"`

	// Status is the HTTP status code to respond with.
	Status int `json:"-"`
	// Err is the internal cause. It is logged but NEVER serialized.
	Err error `json:"-"`

	// requestID is the correlation ID rendered at the envelope top level.
	// Unexported so struct copies never leak it into Details.
	requestID string
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Err != nil {
		return e.Code + ": " + e.Message + ": " + e.Err.Error()
	}
	return e.Code + ": " + e.Message
}

// Unwrap exposes the internal cause for errors.Is/As.
func (e *Error) Unwrap() error { return e.Err }

// envelope is the exact wire format from API.md §8:
//
//	{"error": {...}, "request_id": "..."}
type envelope struct {
	Error     errorBody `json:"error"`
	RequestID string    `json:"request_id,omitempty"`
}

type errorBody struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Retryable bool           `json:"retryable"`
	Details   map[string]any `json:"details,omitempty"`
}

// WithRequestID returns a shallow copy carrying the correlation ID for
// serialization. The original is unchanged.
func (e *Error) WithRequestID(requestID string) *Error {
	clone := *e
	clone.requestID = requestID
	return &clone
}

// MarshalJSON renders the API.md §8 envelope: error body plus top-level
// request_id. Status and Err are never serialized.
func (e *Error) MarshalJSON() ([]byte, error) {
	return json.Marshal(envelope{
		Error: errorBody{
			Code:      e.Code,
			Message:   e.Message,
			Retryable: e.Retryable,
			Details:   e.Details,
		},
		RequestID: e.requestID,
	})
}

// --- Constructors -----------------------------------------------------------

// InvalidRequest builds a 400 error.
func InvalidRequest(message string, details map[string]any) *Error {
	return &Error{Code: CodeInvalidRequest, Message: message, Status: http.StatusBadRequest, Details: details}
}

// Unauthorized builds a 401 error.
func Unauthorized(message string) *Error {
	if message == "" {
		message = "Authentication is required."
	}
	return &Error{Code: CodeUnauthorized, Message: message, Status: http.StatusUnauthorized}
}

// Forbidden builds a 403 error.
func Forbidden(message string) *Error {
	if message == "" {
		message = "You do not have permission to perform this action."
	}
	return &Error{Code: CodeForbidden, Message: message, Status: http.StatusForbidden}
}

// NotFound builds a 404 error.
func NotFound(message string) *Error {
	if message == "" {
		message = "The requested resource was not found."
	}
	return &Error{Code: CodeNotFound, Message: message, Status: http.StatusNotFound}
}

// Conflict builds a 409 error.
func Conflict(message string, details map[string]any) *Error {
	return &Error{Code: CodeConflict, Message: message, Status: http.StatusConflict, Details: details}
}

// PayloadTooLarge builds a 413 error.
func PayloadTooLarge(message string) *Error {
	if message == "" {
		message = "The request body is too large."
	}
	return &Error{Code: CodePayloadTooLarge, Message: message, Status: http.StatusRequestEntityTooLarge, Retryable: false}
}

// Internal builds a 500 error. The cause is logged server-side, never sent.
func Internal(cause error) *Error {
	return &Error{
		Code:      CodeInternal,
		Message:   "An internal error occurred. Please reference the request ID when reporting this issue.",
		Status:    http.StatusInternalServerError,
		Retryable: false,
		Err:       cause,
	}
}

// ServiceUnavailable builds a retryable 503 error.
func ServiceUnavailable(message string) *Error {
	return &Error{Code: CodeServiceUnavailable, Message: message, Status: http.StatusServiceUnavailable, Retryable: true}
}

// DatabaseUnavailable builds a retryable 503 for DB-backed routes when the
// control-plane database is unreachable (graceful degradation).
func DatabaseUnavailable() *Error {
	return &Error{
		Code:      CodeDatabaseUnavailable,
		Message:   "The control-plane database is currently unavailable.",
		Status:    http.StatusServiceUnavailable,
		Retryable: true,
	}
}

// FromError coerces any error into an API Error. Non-API errors become
// internal errors so their details never leak to clients.
func FromError(err error) *Error {
	var apiErr *Error
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return Internal(err)
}
