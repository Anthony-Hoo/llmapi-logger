package orgreport

import "errors"

var (
	// ErrNotFound reports a missing group, project, member or principal.
	ErrNotFound = errors.New("orgreport: not found")
	// ErrInvalid reports invalid administrator input or rules.
	ErrInvalid = errors.New("orgreport: invalid input")
	// ErrUnavailable reports that persistence is not available.
	ErrUnavailable = errors.New("orgreport: unavailable")
	// ErrConflict reports a uniqueness or reference conflict.
	ErrConflict = errors.New("orgreport: conflict")
)
