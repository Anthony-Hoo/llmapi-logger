package orgreport

import (
	"errors"
	"fmt"
	"strings"
)

// Org catalog objects a ValidationError can name.
const (
	ObjectCatalog   = "catalog"
	ObjectGroup     = "group"
	ObjectProject   = "project"
	ObjectMember    = "member"
	ObjectPrincipal = "principal"
)

// Stable reasons of a ValidationError. They describe the rule that failed,
// never the submitted value.
const (
	ReasonEmpty                 = "empty"
	ReasonTooLong               = "too_long"
	ReasonTooMany               = "too_many"
	ReasonSurroundingWhitespace = "surrounding_whitespace"
	ReasonInvalidCharacter      = "invalid_character"
	ReasonInvalidValue          = "invalid_value"
	ReasonInvalidID             = "invalid_id"
	ReasonDuplicate             = "duplicate"
	ReasonUnknownGroup          = "unknown_group"
	ReasonNotASingleName        = "not_a_single_name"
	ReasonHasProjects           = "has_projects"
	ReasonHasMembers            = "has_members"
	ReasonRequired              = "required"
	ReasonConflictingEdit       = "set_and_edited"
	ReasonAddAndRemove          = "added_and_removed"
	ReasonNotPresent            = "not_present"
)

// ValidationError is an org catalog validation failure with a safe reason
// code and the position of the offending field, for callers that must tell
// a user which entry is wrong (the agent facade). The web handler only tests
// errors.Is(err, ErrInvalid) / errors.Is(err, ErrConflict) and prints a fixed
// sentence, and Error() returns exactly the text the error had before it was
// typed, so nothing the web layer shows changes.
//
// Object and ID name the catalog object (ID is the group or project id, the
// member's user id or the principal id; 0 for an object not created yet).
// Field is the JSON path inside that object, e.g. "name", "group_id",
// "rules[2].pattern"; "" when the failure concerns the object as a whole.
// The agent entries of Service report every failure against the object being
// changed: the published catalog compiled, so only that change can have
// broken it.
type ValidationError struct {
	Object  string
	ID      int64
	Kind    string // principal kind, "" otherwise
	Field   string
	Reason  string
	Message string
	// Conflict is true for an ErrConflict (a uniqueness or reference
	// conflict), false for an ErrInvalid.
	Conflict bool
}

func (err *ValidationError) Error() string { return err.sentinel().Error() + ": " + err.Message }

// Unwrap returns ErrConflict or ErrInvalid.
func (err *ValidationError) Unwrap() error { return err.sentinel() }

func (err *ValidationError) sentinel() error {
	if err.Conflict {
		return ErrConflict
	}
	return ErrInvalid
}

func invalidAt(object string, id int64, field, reason, message string) *ValidationError {
	return &ValidationError{Object: object, ID: id, Field: field, Reason: reason, Message: message}
}

func conflictAt(object string, id int64, field, reason, message string) *ValidationError {
	return &ValidationError{Object: object, ID: id, Field: field, Reason: reason, Message: message, Conflict: true}
}

// nameError checks a group or project name; message text as before.
func nameError(object string, id int64, name string) error {
	message := fmt.Sprintf("name must be 1-%d bytes without surrounding whitespace", MaxNameBytes)
	switch {
	case name == "":
		return invalidAt(object, id, "name", ReasonEmpty, message)
	case strings.TrimSpace(name) != name:
		return invalidAt(object, id, "name", ReasonSurroundingWhitespace, message)
	case len(name) > MaxNameBytes:
		return invalidAt(object, id, "name", ReasonTooLong, message)
	}
	if err := validateName(name); err != nil {
		return invalidAt(object, id, "name", ReasonInvalidCharacter, message)
	}
	return nil
}

// retarget reports a failure of a single-object change against that object:
// the published catalog compiled, so only this change can have broken it.
// A duplicate name, for instance, may be detected on the other object of the
// pair, depending on catalog order.
func retarget(err error, object string, id int64, kind string) error {
	var invalid *ValidationError
	if !errors.As(err, &invalid) {
		return err
	}
	copied := *invalid
	if copied.Object != ObjectCatalog {
		copied.Object, copied.ID, copied.Kind = object, id, kind
	}
	return &copied
}
