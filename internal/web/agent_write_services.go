package web

import (
	"context"

	"llmapi-logger/internal/contentpolicy"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/sessionanalysis"
	"llmapi-logger/internal/uaguard"
)

// Optional surfaces the write facade needs beyond the web routes' interfaces
// (contract section 0, row 9): the versioned, check-only and key-only entry
// points of the four services. They are asserted at use; a deployment wired
// with a service that lacks them answers UPSTREAM_UNAVAILABLE for that kind
// rather than falling back to the whole-object web entry points. The
// assertions in internal/app pin the concrete types.

// AgentUARuleWriter is uaguard.Service's agent entry points.
type AgentUARuleWriter interface {
	CheckCreate(uaguard.RulePatch, uaguard.CreateOptions) (uaguard.RuleDiff, error)
	CreateFromPatch(context.Context, uaguard.RulePatch, uaguard.CreateOptions) (uaguard.Rule, error)
	CheckPatch(id, expectedVersion int64, patch uaguard.RulePatch) (uaguard.RuleDiff, error)
	Patch(ctx context.Context, id, expectedVersion int64, patch uaguard.RulePatch) (uaguard.Rule, error)
	CheckDelete(id, expectedVersion int64) (uaguard.Rule, error)
	DeleteIfVersion(ctx context.Context, id, expectedVersion int64) error
}

// AgentContentRuleWriter is contentpolicy.Service's agent entry points.
type AgentContentRuleWriter interface {
	CheckCreate(contentpolicy.RulePatch, contentpolicy.CreateOptions) (contentpolicy.RuleDiff, error)
	CreateFromPatch(context.Context, contentpolicy.RulePatch, contentpolicy.CreateOptions) (contentpolicy.Rule, error)
	CheckPatch(id, expectedVersion int64, change contentpolicy.RuleChange) (contentpolicy.RuleDiff, error)
	Patch(ctx context.Context, id, expectedVersion int64, change contentpolicy.RuleChange) (contentpolicy.Rule, error)
	CheckDelete(id, expectedVersion int64) (contentpolicy.Rule, error)
	DeleteIfVersion(ctx context.Context, id, expectedVersion int64) error
}

// AgentOrgWriter is orgreport.Service's agent entry points.
type AgentOrgWriter interface {
	CheckCreateGroup(orgreport.GroupPatch) (orgreport.GroupDiff, error)
	CreateGroupFromPatch(context.Context, orgreport.GroupPatch) (orgreport.Group, error)
	CheckPatchGroup(id, expectedVersion int64, patch orgreport.GroupPatch) (orgreport.GroupDiff, error)
	PatchGroup(ctx context.Context, id, expectedVersion int64, patch orgreport.GroupPatch) (orgreport.Group, error)
	CheckDeleteGroup(id, expectedVersion int64) (orgreport.Group, error)
	DeleteGroupIfVersion(ctx context.Context, id, expectedVersion int64) error

	CheckCreateProject(orgreport.ProjectPatch) (orgreport.ProjectDiff, error)
	CreateProjectFromPatch(context.Context, orgreport.ProjectPatch) (orgreport.Project, error)
	CheckPatchProject(id, expectedVersion int64, change orgreport.ProjectChange) (orgreport.ProjectDiff, error)
	PatchProject(ctx context.Context, id, expectedVersion int64, change orgreport.ProjectChange) (orgreport.Project, error)
	CheckDeleteProject(id, expectedVersion int64) (orgreport.Project, error)
	DeleteProjectIfVersion(ctx context.Context, id, expectedVersion int64) error

	CheckSetMember(userID, groupID, expectedVersion int64) (orgreport.MemberDiff, error)
	SetMemberIfVersion(ctx context.Context, userID, groupID, expectedVersion int64) (orgreport.Member, error)
	CheckDeleteMember(userID, expectedVersion int64) (orgreport.Member, error)
	DeleteMemberIfVersion(ctx context.Context, userID, expectedVersion int64) error

	CheckSetPrincipal(kind string, id int64, class string, expectedVersion int64) (orgreport.PrincipalDiff, error)
	SetPrincipalIfVersion(ctx context.Context, kind string, id int64, class string, expectedVersion int64) (orgreport.Principal, error)
	CheckDeletePrincipal(kind string, id, expectedVersion int64) (orgreport.Principal, error)
	DeletePrincipalIfVersion(ctx context.Context, kind string, id, expectedVersion int64) error

	CheckPatchSettings(ctx context.Context, expectedVersion int64, change orgreport.SettingsChange) (orgreport.SettingsDiff, error)
	PatchSettings(ctx context.Context, expectedVersion int64, change orgreport.SettingsChange) (orgreport.SettingsView, error)
	CheckResetSettings(ctx context.Context, expectedVersion int64) (orgreport.SettingsDiff, error)
	ResetSettingsIfVersion(ctx context.Context, expectedVersion int64) (orgreport.SettingsView, error)

	WeekState(ctx context.Context, label string) (orgreport.WeekState, error)
}

// AgentAnalysisSettingsWriter is sessionanalysis.SettingsService's agent
// entry points.
type AgentAnalysisSettingsWriter interface {
	CheckPatch(ctx context.Context, expectedVersion int64, patch sessionanalysis.SettingsPatch) (sessionanalysis.SettingsDiff, error)
	Patch(ctx context.Context, expectedVersion int64, patch sessionanalysis.SettingsPatch) (sessionanalysis.SettingsView, error)
	CheckReset(ctx context.Context, expectedVersion int64) (sessionanalysis.SettingsDiff, error)
	ResetIfVersion(ctx context.Context, expectedVersion int64) (sessionanalysis.SettingsView, error)
	SetAPIKey(ctx context.Context, key string) (sessionanalysis.SettingsView, error)
	ClearAPIKey(ctx context.Context) (sessionanalysis.SettingsView, error)
}

// AgentAnalysisRunner is sessionanalysis.QueryService's plan-time reads.
type AgentAnalysisRunner interface {
	RunState(context.Context) (sessionanalysis.RunState, error)
	CalibrationAvailable() bool
}
