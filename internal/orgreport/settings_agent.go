package orgreport

import (
	"context"
	"errors"
	"sort"
	"strings"

	"llmapi-logger/internal/config"
)

// Entry points that edit the saved report settings one field at a time
// (the agent facade, doc/features/25-agent-access.md section 8.2). The web
// route replaces the whole section; these merge only the fields given and
// refuse to write over a change made since the caller read the section.
//
// The version of the section is SettingsView.UpdatedNS: the time the saved
// row was written, in Unix nanoseconds, and 0 while the configuration file
// applies (nothing saved, or a saved row that no longer validates). Every
// save stamps a value above every version this process has seen.

// Reasons of a SettingsError, beyond those of ValidationError.
const (
	// ReasonUnknownClient: a ranked client the vocabulary does not know.
	ReasonUnknownClient = "unknown_client"
)

// SettingsError is an ErrInvalidSettings failure that names the field (the
// JSON name of EditableSettings, e.g. "max_concurrent_roots") and a stable
// reason. Message is the safe sentence the error has always carried, and
// Error() is unchanged, so SettingsMessage and the web mapping see no
// difference.
type SettingsError struct {
	Field   string
	Reason  string
	Message string
}

func (err *SettingsError) Error() string { return ErrInvalidSettings.Error() + ": " + err.Message }

// Unwrap makes errors.Is(err, ErrInvalidSettings) hold.
func (err *SettingsError) Unwrap() error { return ErrInvalidSettings }

// settingsFields maps the configuration paths the validators name to the
// fields of EditableSettings. internal/config only returns text, so the
// field is read from the message's leading path.
var settingsFields = []struct{ prefix, field string }{
	{"org_reports.idle_gap_seconds", "idle_gap_seconds"},
	{"org_reports.ranked_clients", "ranked_clients"},
	{"org_reports.anomaly.max_concurrent_roots", "max_concurrent_roots"},
	{"org_reports.anomaly.max_single_request_roots", "max_single_request_roots"},
}

func settingsError(reason, message string) *SettingsError {
	failure := &SettingsError{Reason: reason, Message: message}
	for _, known := range settingsFields {
		if strings.HasPrefix(message, known.prefix+" ") {
			failure.Field = known.field
			break
		}
	}
	return failure
}

// Version returns the section's version (UpdatedNS; 0 for the file).
func (view SettingsView) Version() int64 { return view.UpdatedNS }

// SettingsPatch names the fields to change; nil keeps the value. Decoding
// into it with DisallowUnknownFields rejects any other field.
type SettingsPatch struct {
	IdleGapSeconds        *int      `json:"idle_gap_seconds,omitempty"`
	RankedClients         *[]string `json:"ranked_clients,omitempty"`
	MaxConcurrentRoots    *int      `json:"max_concurrent_roots,omitempty"`
	MaxSingleRequestRoots *int      `json:"max_single_request_roots,omitempty"`
}

// SettingsListEdit lists ranked clients to add or remove. Keys compare
// trimmed and exactly (keys are lower-case vocabulary keys). Adding a present
// key is a no-op; removing an absent one is a *SettingsError
// (ReasonNotPresent), except a key FormRankedClients dropped.
type SettingsListEdit struct {
	RankedClients []string `json:"ranked_clients,omitempty"`
}

// SettingsChange is one settings patch.
type SettingsChange struct {
	Set    SettingsPatch
	Add    SettingsListEdit
	Remove SettingsListEdit
}

// SettingsDiff is what a settings write would do. Version is the version
// the section had; Changed lists changed JSON field names; DroppedClients
// are stored ranked clients the vocabulary no longer knows, which the page
// drops when it loads the form and the patch drops the same way.
type SettingsDiff struct {
	Version        int64            `json:"version"`
	Before         EditableSettings `json:"before"`
	After          EditableSettings `json:"after"`
	Changed        []string         `json:"changed"`
	DroppedClients []string         `json:"dropped_clients"`
}

// FormRankedClients does to a ranked-clients list what the settings page
// does when it loads the form and before it submits: trim, drop blanks and
// duplicates, sort, and drop keys the vocabulary no longer knows (returned
// as dropped). With an unknown vocabulary nothing is dropped.
func (service *Service) FormRankedClients(clients []string) (kept, dropped []string) {
	kept = make([]string, 0, len(clients))
	for _, client := range dedupeSorted(clients) {
		if len(service.unknownClients([]string{client})) != 0 {
			dropped = append(dropped, client)
			continue
		}
		kept = append(kept, client)
	}
	return kept, dropped
}

func dedupeSorted(clients []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(clients))
	for _, client := range clients {
		client = strings.TrimSpace(client)
		if client == "" || seen[client] {
			continue
		}
		seen[client] = true
		out = append(out, client)
	}
	sort.Strings(out)
	return out
}

// CheckPatchSettings runs every check PatchSettings runs, without saving.
// expectedVersion may be AnyVersion.
func (service *Service) CheckPatchSettings(ctx context.Context, expectedVersion int64, change SettingsChange) (SettingsDiff, error) {
	if service.saved == nil {
		return SettingsDiff{}, ErrUnavailable
	}
	service.settingsMu.Lock()
	defer service.settingsMu.Unlock()
	diff, _, _, err := service.prepareSettings(ctx, expectedVersion, change)
	return diff, err
}

// PatchSettings merges change into the section in use and saves it, only
// when the section's version still equals expectedVersion (0: the file
// applies); otherwise ErrVersionConflict and nothing is written. The merged
// section goes through the same validation, save and apply as UpdateSettings.
func (service *Service) PatchSettings(ctx context.Context, expectedVersion int64, change SettingsChange) (SettingsView, error) {
	if service.saved == nil {
		return SettingsView{}, ErrUnavailable
	}
	service.settingsMu.Lock()
	defer service.settingsMu.Unlock()
	diff, candidate, next, err := service.prepareSettings(ctx, exact(expectedVersion), change)
	if err != nil {
		return SettingsView{}, err
	}
	return service.saveSettings(ctx, candidate, next, diff.Version+1)
}

// CheckResetSettings reports what ResetSettingsIfVersion would do.
// expectedVersion may be AnyVersion.
func (service *Service) CheckResetSettings(ctx context.Context, expectedVersion int64) (SettingsDiff, error) {
	if service.saved == nil {
		return SettingsDiff{}, ErrUnavailable
	}
	service.settingsMu.Lock()
	defer service.settingsMu.Unlock()
	effective, version := service.currentSettings(ctx)
	if !versionMatches(version, expectedVersion) {
		return SettingsDiff{}, ErrVersionConflict
	}
	if _, err := service.settingsFor(service.file); err != nil {
		return SettingsDiff{}, err
	}
	return settingsDiff(version, editableOf(effective), editableOf(service.file), nil), nil
}

// ResetSettingsIfVersion drops the saved section only when its version
// still equals expectedVersion.
func (service *Service) ResetSettingsIfVersion(ctx context.Context, expectedVersion int64) (SettingsView, error) {
	if service.saved == nil {
		return SettingsView{}, ErrUnavailable
	}
	service.settingsMu.Lock()
	defer service.settingsMu.Unlock()
	if _, version := service.currentSettings(ctx); version != exact(expectedVersion) {
		return SettingsView{}, ErrVersionConflict
	}
	return service.resetSettings(ctx)
}

// prepareSettings merges and validates a change against the section in use.
// The caller holds settingsMu.
func (service *Service) prepareSettings(ctx context.Context, expectedVersion int64, change SettingsChange) (SettingsDiff, config.OrgReportsConfig, Settings, error) {
	effective, version := service.currentSettings(ctx)
	if !versionMatches(version, expectedVersion) {
		return SettingsDiff{}, config.OrgReportsConfig{}, Settings{}, ErrVersionConflict
	}
	before := editableOf(effective)
	edited := editableOf(effective)
	set := change.Set
	if set.RankedClients != nil && (len(change.Add.RankedClients) > 0 || len(change.Remove.RankedClients) > 0) {
		return SettingsDiff{}, config.OrgReportsConfig{}, Settings{}, &SettingsError{Field: "ranked_clients", Reason: ReasonConflictingEdit, Message: "org_reports.ranked_clients cannot be both replaced and edited"}
	}
	if set.IdleGapSeconds != nil {
		edited.IdleGapSeconds = *set.IdleGapSeconds
	}
	if set.MaxConcurrentRoots != nil {
		edited.MaxConcurrentRoots = *set.MaxConcurrentRoots
	}
	if set.MaxSingleRequestRoots != nil {
		edited.MaxSingleRequestRoots = *set.MaxSingleRequestRoots
	}
	var dropped []string
	if set.RankedClients != nil {
		edited.RankedClients = dedupeSorted(*set.RankedClients)
	} else {
		var kept []string
		kept, dropped = service.FormRankedClients(edited.RankedClients)
		clients, err := editClients(before.RankedClients, kept, change.Add.RankedClients, change.Remove.RankedClients)
		if err != nil {
			return SettingsDiff{}, config.OrgReportsConfig{}, Settings{}, err
		}
		edited.RankedClients = dedupeSorted(clients)
	}
	candidate := overlaySettings(service.file, edited)
	next, err := service.settingsFor(candidate)
	if err != nil {
		return SettingsDiff{}, config.OrgReportsConfig{}, Settings{}, err
	}
	if err := service.checkVocabulary(candidate.RankedClients); err != nil {
		return SettingsDiff{}, config.OrgReportsConfig{}, Settings{}, err
	}
	return settingsDiff(version, before, editableOf(candidate), dropped), candidate, next, nil
}

// editClients removes then adds keys. Presence for removal is judged on the
// stored list, so removing a key the vocabulary dropped is not an error.
func editClients(stored, kept, add, remove []string) ([]string, error) {
	out := append([]string{}, kept...)
	adding := map[string]bool{}
	for _, client := range add {
		adding[strings.TrimSpace(client)] = true
	}
	for _, client := range remove {
		wanted := strings.TrimSpace(client)
		if adding[wanted] {
			return nil, &SettingsError{Field: "ranked_clients", Reason: ReasonAddAndRemove, Message: "org_reports.ranked_clients cannot add and remove the same client"}
		}
		present := false
		for _, existing := range stored {
			present = present || strings.TrimSpace(existing) == wanted
		}
		if !present {
			return nil, &SettingsError{Field: "ranked_clients", Reason: ReasonNotPresent, Message: "org_reports.ranked_clients does not list a client to remove"}
		}
		kept := out[:0:0]
		for _, existing := range out {
			if existing != wanted {
				kept = append(kept, existing)
			}
		}
		out = kept
	}
	for _, client := range add {
		out = append(out, client)
	}
	return out, nil
}

func settingsDiff(version int64, before, after EditableSettings, dropped []string) SettingsDiff {
	changed := []string{}
	if before.IdleGapSeconds != after.IdleGapSeconds {
		changed = append(changed, "idle_gap_seconds")
	}
	if strings.Join(before.RankedClients, "\x00") != strings.Join(after.RankedClients, "\x00") || len(before.RankedClients) != len(after.RankedClients) {
		changed = append(changed, "ranked_clients")
	}
	if before.MaxConcurrentRoots != after.MaxConcurrentRoots {
		changed = append(changed, "max_concurrent_roots")
	}
	if before.MaxSingleRequestRoots != after.MaxSingleRequestRoots {
		changed = append(changed, "max_single_request_roots")
	}
	if dropped == nil {
		dropped = []string{}
	}
	return SettingsDiff{Version: version, Before: before, After: after, Changed: changed, DroppedClients: dropped}
}

// WeekState is what Regenerate checks about a week, plus whether a snapshot
// is stored for it, read without computing anything.
type WeekState struct {
	Week    string `json:"week"`
	StartNS int64  `json:"start_ns,string"`
	EndNS   int64  `json:"end_ns,string"`
	// Ended is Regenerate's condition: the week is over.
	Ended bool `json:"ended"`
	// Frozen reports a stored snapshot; FrozenAtNS and GeneratedAtNS are its
	// times, 0 without one.
	Frozen        bool  `json:"frozen"`
	FrozenAtNS    int64 `json:"frozen_at_ns,string"`
	GeneratedAtNS int64 `json:"generated_at_ns,string"`
}

// WeekState checks a week label the way Regenerate does, in its order:
// snapshots must be available (else ErrUnavailable), the label must be the
// first day of a report week (else an error matching ErrInvalid; an empty
// label is invalid here, where Regenerate would take the current week).
// Whether the week has ended is reported, not enforced. It loads the stored
// snapshot, if any, and recomputes nothing.
func (service *Service) WeekState(ctx context.Context, label string) (WeekState, error) {
	if service.snapshots == nil {
		return WeekState{}, ErrUnavailable
	}
	if label == "" {
		return WeekState{}, errors.Join(ErrInvalid, errors.New("orgreport: week is required"))
	}
	week, err := service.resolveWeek(label)
	if err != nil {
		return WeekState{}, err
	}
	state := WeekState{Week: week.Label(), StartNS: week.Start.UnixNano(), EndNS: week.End.UnixNano(), Ended: service.now().After(week.End)}
	snapshot, exists, err := service.snapshots.LoadWeeklySnapshot(ctx, week.Label())
	if err != nil {
		return WeekState{}, err
	}
	if exists {
		state.Frozen, state.FrozenAtNS, state.GeneratedAtNS = true, snapshot.FrozenAtNS, snapshot.GeneratedAtNS
	}
	return state, nil
}

// Version is the version of the week's stored state: the generated_at of
// its snapshot, 0 while none is stored. Every snapshot write stamps a value
// above the previous one.
func (state WeekState) Version() int64 { return state.GeneratedAtNS }

// RegenerateIfVersion is Regenerate only while the week's stored state is
// still the one the caller saw (WeekState.Version; 0: no snapshot):
// otherwise ErrVersionConflict and nothing is written. The comparison and
// the write hold the snapshot lock, so no other freeze or regeneration can
// land in between. Waiting for the lock gives up when ctx ends: the error then
// matches ErrNotStarted (and ctx's error), and nothing was computed or
// written.
func (service *Service) RegenerateIfVersion(ctx context.Context, label string, expectedVersion int64) error {
	if service.snapshots == nil {
		return ErrUnavailable
	}
	week, err := service.resolveWeek(label)
	if err != nil {
		return err
	}
	if !service.now().After(week.End) {
		return ErrInvalid
	}
	if err := service.job.freezeLock.lock(ctx); err != nil {
		return notStarted(err)
	}
	defer service.job.freezeLock.unlock()
	snapshot, exists, err := service.snapshots.LoadWeeklySnapshot(ctx, week.Label())
	if err != nil {
		return err
	}
	var version int64
	if exists {
		version = snapshot.GeneratedAtNS
	}
	if version != expectedVersion {
		return ErrVersionConflict
	}
	return service.freezeLocked(ctx, week)
}
