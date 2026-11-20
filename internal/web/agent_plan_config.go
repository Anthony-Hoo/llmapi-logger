package web

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/contentpolicy"
	"llmapi-logger/internal/orgreport"
	"llmapi-logger/internal/query"
	"llmapi-logger/internal/sessionanalysis"
	"llmapi-logger/internal/uaguard"
)

// config.set, config.remove and config.reset (contract sections 4.5.1 and
// 4.5.2). Each kind decodes set/add/remove into its service's patch types and
// asks the service's check-only entry for the merged, normalised object; the
// service does what the web form does in the browser (section 4.7), so the
// facade adds no normalisation of its own. The plan's closure calls the
// versioned write entry with the version the check saw.

const (
	effectNoChange   = "Nothing changes: every given value is already in effect. Applying the plan still stamps a new version."
	effectLiveRule   = "Takes effect on live proxy traffic as soon as the plan is applied."
	effectCatalog    = "Weeks that are not frozen yet are attributed again with the changed catalog; frozen weeks keep their snapshot until regenerated."
	effectWeekly     = "Applies to weeks that are not frozen yet; frozen weeks keep their snapshot until regenerated."
	effectAnalysis   = "The next session analysis run uses these settings; a run in progress keeps the settings it started with."
	effectModelMoved = "The model or its address changes: the next run labels every input pack with it."
	effectDeleteOnly = "There is no recycle bin: extras.deleted_object is the only copy of the object after the plan is applied."
	// effectIrreversible begins the line every plan of an operation that
	// cannot be undone carries (contract section 0.1 item 107).
	effectIrreversible = "This cannot be undone through this interface"
)

func (handler *managementHandler) planConfigSet(ctx context.Context, request agentPlanRequest) (*agentPlan, error) {
	if err := checkWriteKind(request.Kind, agentapi.WriteKinds); err != nil {
		return nil, err
	}
	if err := canonicalPlanFields(&request); err != nil {
		return nil, err
	}
	if len(request.Set) == 0 && len(request.Add) == 0 && len(request.Remove) == 0 {
		return nil, fieldFailure("set", "nothing to change: give set, add or remove")
	}
	if err := checkListConflicts(request); err != nil {
		return nil, err
	}
	creating := request.ID == nil
	switch request.Kind {
	case "weekly-settings", "analysis-settings":
		if !creating {
			return nil, fieldFailure("id", request.Kind+" has no id")
		}
		creating = false
	case "member", "principal":
		if creating {
			return nil, fieldFailure("id", request.Kind+" needs id: a change of "+request.Kind+" is always to an existing user or token")
		}
	}
	if creating {
		for _, edit := range []struct {
			name   string
			values map[string]json.RawMessage
		}{{"add", request.Add}, {"remove", request.Remove}} {
			if len(edit.values) > 0 {
				return nil, fieldFailure(edit.name, edit.name+" is not allowed when creating; give the whole list with set")
			}
		}
		if request.ExpectedVersion != nil {
			return nil, fieldFailure("expected_version", "expected_version is not used when creating")
		}
	}
	switch request.Kind {
	case "ua-rule":
		return handler.planUARuleSet(request, creating)
	case "content-rule":
		return handler.planContentRuleSet(request, creating)
	case "group":
		return handler.planGroupSet(request, creating)
	case "project":
		return handler.planProjectSet(ctx, request, creating)
	case "member":
		return handler.planMemberSet(ctx, request)
	case "principal":
		return handler.planPrincipalSet(ctx, request)
	case "weekly-settings":
		return handler.planWeeklySettingsSet(ctx, request)
	default:
		return handler.planAnalysisSettingsSet(ctx, request)
	}
}

func checkWriteKind(kind string, allowed []string) error {
	if kind == "" {
		return fieldFailure("kind", "kind is required")
	}
	if !contains(allowed, kind) {
		return fieldFailure("kind", "kind must be one of "+strings.Join(allowed, ", "))
	}
	return nil
}

// noListEdits refuses add and remove for a kind without list fields.
func noListEdits(kind string, request agentPlanRequest) error {
	for _, edit := range []map[string]json.RawMessage{request.Add, request.Remove} {
		for _, key := range sortedMemberKeys(edit) {
			if isKeyField(key) {
				return fieldFailure(key, keyFieldMessage)
			}
			return fieldFailure(key, kind+" has no list field; use set")
		}
	}
	return nil
}

// agentNumericID is the id of a rule, group or project, or a member's user
// id: a positive decimal string.
func agentNumericID(request agentPlanRequest) (int64, error) {
	if request.ID == nil {
		return 0, fieldFailure("id", "id is required")
	}
	id, ok := parseAgentID(*request.ID, false)
	if !ok || id <= 0 {
		return 0, fieldFailure("id", "id must be a positive decimal number, written as a string")
	}
	return id, nil
}

// agentPrincipalID is a principal's id: user:<id> or token:<id>.
func agentPrincipalID(request agentPlanRequest) (string, int64, error) {
	if request.ID == nil {
		return "", 0, fieldFailure("id", "id is required")
	}
	kind, raw, ok := strings.Cut(*request.ID, ":")
	id, valid := parseAgentID(raw, false)
	if !ok || (kind != orgreport.PrincipalUser && kind != orgreport.PrincipalToken) || !valid || id <= 0 {
		return "", 0, fieldFailure("id", "id of a principal is user:<id> or token:<id>")
	}
	return kind, id, nil
}

func formatAgentID(id int64) string { return strconv.FormatInt(id, 10) }

func changedOrNothing(plan *agentPlan, changed []string) {
	plan.view.ChangedKeys = append([]string{}, changed...)
	if len(changed) == 0 && !plan.view.Creates {
		plan.effect(effectNoChange)
	}
}

func (handler *managementHandler) agentUAWriter() (AgentUARuleWriter, error) {
	writer, ok := handler.rules.(AgentUARuleWriter)
	if handler.rules == nil || !ok {
		return nil, errAgentUnavailable
	}
	return writer, nil
}

func (handler *managementHandler) agentContentWriter() (AgentContentRuleWriter, error) {
	writer, ok := handler.policies.(AgentContentRuleWriter)
	if handler.policies == nil || !ok || !handler.policies.Available() {
		return nil, errAgentUnavailable
	}
	return writer, nil
}

func (handler *managementHandler) agentOrgWriter() (AgentOrgWriter, error) {
	if handler.org == nil {
		return nil, &agentFailure{Code: agentapi.CodeModuleDisabled, Details: map[string]any{"module": agentModuleOrgReports}}
	}
	writer, ok := handler.org.(AgentOrgWriter)
	if !ok {
		return nil, errAgentUnavailable
	}
	return writer, nil
}

func (handler *managementHandler) agentAnalysisSettingsWriter() (AgentAnalysisSettingsWriter, error) {
	if handler.sessionAnalysisSettings == nil {
		return nil, &agentFailure{Code: agentapi.CodeModuleDisabled, Details: map[string]any{"module": agentModuleSessionAnalysis}}
	}
	writer, ok := handler.sessionAnalysisSettings.(AgentAnalysisSettingsWriter)
	if !ok {
		return nil, errAgentUnavailable
	}
	return writer, nil
}

func agentUARuleView(rule uaguard.Rule) agentUARule { return agentUARules([]uaguard.Rule{rule})[0] }

func agentContentRuleView(rule contentpolicy.Rule) agentContentRule {
	return agentContentRules([]contentpolicy.Rule{rule})[0]
}

// ---- ua-rule ----

func (handler *managementHandler) planUARuleSet(request agentPlanRequest, creating bool) (*agentPlan, error) {
	rules, err := handler.agentUAWriter()
	if err != nil {
		return nil, err
	}
	if err := noListEdits("ua-rule", request); err != nil {
		return nil, err
	}
	patch, err := decodeAgentSet[uaguard.RulePatch]("ua-rule", request.Set, nil)
	if err != nil {
		return nil, err
	}
	// A duplicate name is accepted, as the web route accepts it; the plan says
	// so (sameNameEffect).
	options := uaguard.CreateOptions{}
	if creating {
		diff, err := rules.CheckCreate(patch, options)
		if err != nil {
			return nil, err
		}
		plan := newAgentPlan(agentapi.OpConfigSet, agentPlanTarget{Kind: "ua-rule"})
		plan.view.Creates, plan.untrusted = true, true
		plan.view.After = agentUARuleView(diff.After)
		plan.view.ChangedKeys = suppliedFields(request.Kind, request.Set)
		sameNameEffect(plan, "user agent rule", diff.SameName)
		plan.effect(effectLiveRule)
		plan.verify = "llmaudit config show --kind ua-rule"
		plan.apply = func(ctx context.Context) (agentApplied, error) {
			rule, err := rules.CreateFromPatch(ctx, patch, options)
			return agentApplied{ID: formatAgentID(rule.ID), Version: agentVersion(rule.UpdatedAtNS)}, err
		}
		return plan, nil
	}
	id, err := agentNumericID(request)
	if err != nil {
		return nil, err
	}
	expected, err := agentExpectedVersion(request, uaguard.AnyVersion)
	if err != nil {
		return nil, err
	}
	diff, err := rules.CheckPatch(id, expected, patch)
	if err != nil {
		return nil, err
	}
	version := diff.Before.UpdatedAtNS
	plan := newAgentPlan(agentapi.OpConfigSet, agentPlanTarget{Kind: "ua-rule", ID: formatAgentID(id), Version: agentVersion(version)})
	plan.untrusted = true
	plan.view.Before, plan.view.After = agentUARuleView(diff.Before), agentUARuleView(diff.After)
	changedOrNothing(plan, diff.Changed)
	plan.effect(effectLiveRule)
	plan.verify = "llmaudit config show --kind ua-rule"
	plan.apply = func(ctx context.Context) (agentApplied, error) {
		rule, err := rules.Patch(ctx, id, version, patch)
		return agentApplied{Version: agentVersion(rule.UpdatedAtNS)}, err
	}
	return plan, nil
}

// sameNameEffect tells the user, before they agree to a create, that rules
// with the same name exist and which: the create is not refused for it, as
// the web form does not refuse it. extras.same_name lists their ids.
func sameNameEffect(plan *agentPlan, noun string, ids []int64) {
	if len(ids) == 0 {
		return
	}
	listed := make([]string, 0, len(ids))
	for _, id := range ids {
		listed = append(listed, formatAgentID(id))
	}
	plan.view.Extras["same_name"] = listed
	plan.effect("A " + noun + " with this name already exists (id " + strings.Join(listed, ", ") + "); applying the plan creates another one with the same name. To change the existing one instead, make a plan with --id.")
}

// ---- content-rule ----

func (handler *managementHandler) planContentRuleSet(request agentPlanRequest, creating bool) (*agentPlan, error) {
	policies, err := handler.agentContentWriter()
	if err != nil {
		return nil, err
	}
	patch, err := decodeAgentSet[contentpolicy.RulePatch]("content-rule", request.Set, nil)
	if err != nil {
		return nil, err
	}
	options := contentpolicy.CreateOptions{}
	if creating {
		diff, err := policies.CheckCreate(patch, options)
		if err != nil {
			return nil, err
		}
		plan := newAgentPlan(agentapi.OpConfigSet, agentPlanTarget{Kind: "content-rule"})
		plan.view.Creates, plan.untrusted = true, true
		plan.view.After = agentContentRuleView(diff.After)
		plan.view.ChangedKeys = suppliedFields(request.Kind, request.Set)
		sameNameEffect(plan, "content rule", diff.SameName)
		if patch.ScanScopes == nil {
			plan.effect("scan_scopes was not given: all seven scopes are scanned, as the web form preselects.")
		}
		plan.effect(effectLiveRule)
		plan.verify = "llmaudit config show --kind content-rule"
		plan.apply = func(ctx context.Context) (agentApplied, error) {
			rule, err := policies.CreateFromPatch(ctx, patch, options)
			return agentApplied{ID: formatAgentID(rule.ID), Version: agentVersion(rule.UpdatedAtNS)}, err
		}
		return plan, nil
	}
	add, err := decodeAgentListEdit[contentpolicy.RuleListEdit]("content-rule", "add", request.Add)
	if err != nil {
		return nil, err
	}
	remove, err := decodeAgentListEdit[contentpolicy.RuleListEdit]("content-rule", "remove", request.Remove)
	if err != nil {
		return nil, err
	}
	change := contentpolicy.RuleChange{Set: patch, Add: add, Remove: remove}
	id, err := agentNumericID(request)
	if err != nil {
		return nil, err
	}
	expected, err := agentExpectedVersion(request, contentpolicy.AnyVersion)
	if err != nil {
		return nil, err
	}
	diff, err := policies.CheckPatch(id, expected, change)
	if err != nil {
		return nil, err
	}
	version := diff.Before.UpdatedAtNS
	plan := newAgentPlan(agentapi.OpConfigSet, agentPlanTarget{Kind: "content-rule", ID: formatAgentID(id), Version: agentVersion(version)})
	plan.untrusted = true
	plan.view.Before, plan.view.After = agentContentRuleView(diff.Before), agentContentRuleView(diff.After)
	changedOrNothing(plan, diff.Changed)
	if diff.ScopesSubstituted {
		plan.effect("The stored rule has no scan scopes; all seven are used in their place, as the web form does when it opens the rule.")
	}
	plan.effect(effectLiveRule)
	plan.verify = "llmaudit config show --kind content-rule"
	plan.apply = func(ctx context.Context) (agentApplied, error) {
		rule, err := policies.Patch(ctx, id, version, change)
		return agentApplied{Version: agentVersion(rule.UpdatedAtNS)}, err
	}
	return plan, nil
}

// ---- group ----

func (handler *managementHandler) planGroupSet(request agentPlanRequest, creating bool) (*agentPlan, error) {
	org, err := handler.agentOrgWriter()
	if err != nil {
		return nil, err
	}
	if err := noListEdits("group", request); err != nil {
		return nil, err
	}
	patch, err := decodeAgentSet[orgreport.GroupPatch]("group", request.Set, nil)
	if err != nil {
		return nil, err
	}
	if creating {
		diff, err := org.CheckCreateGroup(patch)
		if err != nil {
			return nil, err
		}
		plan := newAgentPlan(agentapi.OpConfigSet, agentPlanTarget{Kind: "group"})
		plan.view.Creates, plan.untrusted = true, true
		plan.view.After = agentOrgGroupOf(diff.After)
		plan.view.ChangedKeys = suppliedFields(request.Kind, request.Set)
		plan.effect(effectCatalog)
		plan.verify = "llmaudit config show --kind org"
		plan.apply = func(ctx context.Context) (agentApplied, error) {
			group, err := org.CreateGroupFromPatch(ctx, patch)
			return agentApplied{ID: formatAgentID(group.ID), Version: agentVersion(group.UpdatedAtNS)}, err
		}
		return plan, nil
	}
	id, err := agentNumericID(request)
	if err != nil {
		return nil, err
	}
	expected, err := agentExpectedVersion(request, orgreport.AnyVersion)
	if err != nil {
		return nil, err
	}
	diff, err := org.CheckPatchGroup(id, expected, patch)
	if err != nil {
		return nil, err
	}
	version := diff.Before.UpdatedAtNS
	plan := newAgentPlan(agentapi.OpConfigSet, agentPlanTarget{Kind: "group", ID: formatAgentID(id), Version: agentVersion(version)})
	plan.untrusted = true
	plan.view.Before, plan.view.After = agentOrgGroupOf(diff.Before), agentOrgGroupOf(diff.After)
	changedOrNothing(plan, diff.Changed)
	plan.effect(effectCatalog)
	plan.verify = "llmaudit config show --kind org"
	plan.apply = func(ctx context.Context) (agentApplied, error) {
		group, err := org.PatchGroup(ctx, id, version, patch)
		return agentApplied{Version: agentVersion(group.UpdatedAtNS)}, err
	}
	return plan, nil
}

// ---- project ----

func (handler *managementHandler) planProjectSet(ctx context.Context, request agentPlanRequest, creating bool) (*agentPlan, error) {
	org, err := handler.agentOrgWriter()
	if err != nil {
		return nil, err
	}
	patch, err := decodeAgentSet[orgreport.ProjectPatch]("project", request.Set, func(field string) bool { return field == "group_id" })
	if err != nil {
		return nil, err
	}
	var plan *agentPlan
	var after orgreport.Project
	var projectID int64
	if creating {
		diff, err := org.CheckCreateProject(patch)
		if err != nil {
			return nil, err
		}
		after = diff.After
		plan = newAgentPlan(agentapi.OpConfigSet, agentPlanTarget{Kind: "project"})
		plan.view.Creates = true
		plan.view.After = agentOrgProjectOf(diff.After)
		plan.view.ChangedKeys = suppliedFields(request.Kind, request.Set)
		plan.apply = func(ctx context.Context) (agentApplied, error) {
			project, err := org.CreateProjectFromPatch(ctx, patch)
			return agentApplied{ID: formatAgentID(project.ID), Version: agentVersion(project.UpdatedAtNS)}, err
		}
	} else {
		add, err := decodeAgentListEdit[orgreport.ProjectListEdit]("project", "add", request.Add)
		if err != nil {
			return nil, err
		}
		remove, err := decodeAgentListEdit[orgreport.ProjectListEdit]("project", "remove", request.Remove)
		if err != nil {
			return nil, err
		}
		change := orgreport.ProjectChange{Set: patch, Add: add, Remove: remove}
		id, err := agentNumericID(request)
		if err != nil {
			return nil, err
		}
		expected, err := agentExpectedVersion(request, orgreport.AnyVersion)
		if err != nil {
			return nil, err
		}
		diff, err := org.CheckPatchProject(id, expected, change)
		if err != nil {
			return nil, err
		}
		after, projectID = diff.After, id
		version := diff.Before.UpdatedAtNS
		plan = newAgentPlan(agentapi.OpConfigSet, agentPlanTarget{Kind: "project", ID: formatAgentID(id), Version: agentVersion(version)})
		plan.view.Before, plan.view.After = agentOrgProjectOf(diff.Before), agentOrgProjectOf(diff.After)
		changedOrNothing(plan, diff.Changed)
		plan.apply = func(ctx context.Context) (agentApplied, error) {
			project, err := org.PatchProject(ctx, id, version, change)
			return agentApplied{Version: agentVersion(project.UpdatedAtNS)}, err
		}
	}
	plan.untrusted = true
	plan.verify = "llmaudit config show --kind org"
	plan.effect(effectCatalog)
	if len(after.Rules) == 0 {
		plan.effect("The project has no rules and matches no request; no preview is attached.")
		return plan, nil
	}
	// The preview the web form offers on request, attached automatically.
	preview, err := handler.org.Preview(ctx, orgreport.PreviewInput{GroupID: after.GroupID, Rules: after.Rules, ProjectID: projectID})
	if err != nil {
		return nil, err
	}
	plan.view.Extras["preview"] = agentPreview{Requests: preview.Requests, Identities: preview.Identities, Users: preview.Users,
		FromUnattributed: preview.Unattributed, FromOtherProjects: preview.OtherProject}
	return plan, nil
}

// ---- member and principal ----

// The web routes take these bodies too (PUT …/members/{user_id} and
// …/principals/{kind}/{id}); the services take the values as arguments.
type agentMemberPatch struct {
	GroupID *int64 `json:"group_id"`
}

type agentPrincipalPatch struct {
	Class *string `json:"class"`
}

// callerSeen reports whether this system has seen a NewAPI user or token: a
// user in the NewAPI user directory, or a user or token named by any audit
// record. directory and audits report which of the two sources answered. The
// web routes for members and principals accept any positive id
// (org_admin_api.go); the plan says so when the id is not a caller seen here.
func (handler *managementHandler) callerSeen(ctx context.Context, kind string, id int64) (seen, directory, audits bool) {
	if kind == orgreport.PrincipalUser && handler.users != nil {
		snapshot := handler.users.Snapshot()
		directory = !snapshot.RefreshedAt.IsZero() || len(snapshot.Users) > 0
		for _, user := range snapshot.Users {
			if user.ID == id {
				return true, true, false
			}
		}
	}
	if handler.query == nil {
		return false, directory, false
	}
	filter := query.Filter{}
	if kind == orgreport.PrincipalUser {
		filter.NewAPIUserID = &id
	} else {
		filter.NewAPITokenID = &id
	}
	page, err := handler.query.List(ctx, filter, query.Cursor{}, 1)
	if err != nil {
		return false, directory, false
	}
	return len(page.Items) > 0, directory, true
}

// unseenCallerEffect is the effect line of a member or principal plan whose
// id is not a caller this system has seen, "" when it is one. It names only
// the sources that were actually consulted.
func (handler *managementHandler) unseenCallerEffect(ctx context.Context, kind string, id int64) string {
	seen, directory, audits := handler.callerSeen(ctx, kind, id)
	noun, check := "User "+formatAgentID(id), "`llmaudit callers list` or `llmaudit requests list --user-id "+formatAgentID(id)+"`"
	if kind == orgreport.PrincipalToken {
		noun, check = "Token "+formatAgentID(id), "`llmaudit requests list --token-id "+formatAgentID(id)+"`"
	}
	var where []string
	if directory {
		where = append(where, "not in the NewAPI user directory")
	}
	if audits {
		where = append(where, "no audit record names it")
	}
	switch {
	case seen:
		return ""
	case len(where) == 0:
		return "Whether " + strings.ToLower(noun[:1]) + noun[1:] + " exists could not be checked here (neither the NewAPI user directory nor the audit records could answer). The web page accepts any id as well; make sure it is the intended one."
	}
	return noun + " is not among the callers this system has seen (" + strings.Join(where, ", and ") + "). The web page accepts any id as well, so the plan is valid, but check the id with " + check + " before applying."
}
func (handler *managementHandler) planMemberSet(ctx context.Context, request agentPlanRequest) (*agentPlan, error) {
	org, err := handler.agentOrgWriter()
	if err != nil {
		return nil, err
	}
	if err := noListEdits("member", request); err != nil {
		return nil, err
	}
	patch, err := decodeAgentSet[agentMemberPatch]("member", request.Set, nil)
	if err != nil {
		return nil, err
	}
	if patch.GroupID == nil {
		return nil, fieldFailure("group_id", "group_id is required: the group to put the user in")
	}
	userID, err := agentNumericID(request)
	if err != nil {
		return nil, err
	}
	expected, err := agentExpectedVersion(request, orgreport.AnyVersion)
	if err != nil {
		return nil, err
	}
	groupID := *patch.GroupID
	diff, err := org.CheckSetMember(userID, groupID, expected)
	if err != nil {
		return nil, err
	}
	var version int64
	changed := []string{"group_id"}
	plan := newAgentPlan(agentapi.OpConfigSet, agentPlanTarget{Kind: "member", ID: formatAgentID(userID)})
	if diff.Before != nil {
		version = diff.Before.UpdatedAtNS
		plan.view.Before = agentOrgMemberOf(*diff.Before)
		if diff.Before.GroupID == groupID {
			changed = []string{}
		}
	}
	plan.view.Target.Version = agentVersion(version)
	plan.view.After = agentOrgMemberOf(diff.After)
	changedOrNothing(plan, changed)
	if effect := handler.unseenCallerEffect(ctx, orgreport.PrincipalUser, userID); effect != "" {
		plan.view.Extras["caller_seen"] = false
		plan.effect(effect)
	}
	plan.effect(effectCatalog)
	plan.verify = "llmaudit config show --kind org"
	plan.apply = func(ctx context.Context) (agentApplied, error) {
		member, err := org.SetMemberIfVersion(ctx, userID, groupID, version)
		return agentApplied{Version: agentVersion(member.UpdatedAtNS)}, err
	}
	return plan, nil
}

func (handler *managementHandler) planPrincipalSet(ctx context.Context, request agentPlanRequest) (*agentPlan, error) {
	org, err := handler.agentOrgWriter()
	if err != nil {
		return nil, err
	}
	if err := noListEdits("principal", request); err != nil {
		return nil, err
	}
	patch, err := decodeAgentSet[agentPrincipalPatch]("principal", request.Set, nil)
	if err != nil {
		return nil, err
	}
	if patch.Class == nil {
		return nil, fieldFailure("class", "class is required: human or service")
	}
	kind, id, err := agentPrincipalID(request)
	if err != nil {
		return nil, err
	}
	expected, err := agentExpectedVersion(request, orgreport.AnyVersion)
	if err != nil {
		return nil, err
	}
	class := *patch.Class
	diff, err := org.CheckSetPrincipal(kind, id, class, expected)
	if err != nil {
		return nil, err
	}
	var version int64
	changed := []string{"class"}
	plan := newAgentPlan(agentapi.OpConfigSet, agentPlanTarget{Kind: "principal", ID: kind + ":" + formatAgentID(id)})
	if diff.Before != nil {
		version = diff.Before.UpdatedAtNS
		plan.view.Before = agentOrgPrincipalOf(*diff.Before)
		if diff.Before.Class == diff.After.Class {
			changed = []string{}
		}
	}
	plan.view.Target.Version = agentVersion(version)
	plan.view.After = agentOrgPrincipalOf(diff.After)
	changedOrNothing(plan, changed)
	if effect := handler.unseenCallerEffect(ctx, kind, id); effect != "" {
		plan.view.Extras["caller_seen"] = false
		plan.effect(effect)
	}
	plan.effect(effectCatalog)
	plan.verify = "llmaudit config show --kind org"
	plan.apply = func(ctx context.Context) (agentApplied, error) {
		principal, err := org.SetPrincipalIfVersion(ctx, kind, id, class, version)
		return agentApplied{Version: agentVersion(principal.UpdatedAtNS)}, err
	}
	return plan, nil
}

// ---- the two settings sections ----

func (handler *managementHandler) planWeeklySettingsSet(ctx context.Context, request agentPlanRequest) (*agentPlan, error) {
	org, err := handler.agentOrgWriter()
	if err != nil {
		return nil, err
	}
	patch, err := decodeAgentSet[orgreport.SettingsPatch]("weekly-settings", request.Set, nil)
	if err != nil {
		return nil, err
	}
	add, err := decodeAgentListEdit[orgreport.SettingsListEdit]("weekly-settings", "add", request.Add)
	if err != nil {
		return nil, err
	}
	remove, err := decodeAgentListEdit[orgreport.SettingsListEdit]("weekly-settings", "remove", request.Remove)
	if err != nil {
		return nil, err
	}
	change := orgreport.SettingsChange{Set: patch, Add: add, Remove: remove}
	expected, err := agentExpectedVersion(request, orgreport.AnyVersion)
	if err != nil {
		return nil, err
	}
	diff, err := org.CheckPatchSettings(ctx, expected, change)
	if err != nil {
		return nil, err
	}
	version := diff.Version
	plan := newAgentPlan(agentapi.OpConfigSet, agentPlanTarget{Kind: "weekly-settings", Version: agentVersion(version)})
	plan.view.Before, plan.view.After = agentWeeklySettingsValuesOf(diff.Before), agentWeeklySettingsValuesOf(diff.After)
	changedOrNothing(plan, diff.Changed)
	if len(diff.DroppedClients) > 0 {
		plan.view.Extras["dropped_clients"] = append([]string{}, diff.DroppedClients...)
		plan.effect("Stored ranked clients the vocabulary no longer knows are dropped, as the web form drops them: " + strings.Join(diff.DroppedClients, ", ") + ".")
	}
	plan.effect(effectWeekly)
	plan.verify = "llmaudit config show --kind weekly-settings"
	plan.apply = func(ctx context.Context) (agentApplied, error) {
		view, err := org.PatchSettings(ctx, version, change)
		return agentApplied{Version: agentVersion(view.UpdatedNS)}, err
	}
	return plan, nil
}

// analysisSettingsPatch decodes the flat, dotted set of analysis-settings.
func analysisSettingsPatch(set map[string]json.RawMessage) (sessionanalysis.SettingsPatch, error) {
	return decodeAgentSet[sessionanalysis.SettingsPatch]("analysis-settings", set, nil)
}

func (handler *managementHandler) planAnalysisSettingsSet(ctx context.Context, request agentPlanRequest) (*agentPlan, error) {
	settings, err := handler.agentAnalysisSettingsWriter()
	if err != nil {
		return nil, err
	}
	if err := noListEdits("analysis-settings", request); err != nil {
		return nil, err
	}
	patch, err := analysisSettingsPatch(request.Set)
	if err != nil {
		return nil, err
	}
	expected, err := agentExpectedVersion(request, sessionanalysis.AnyVersion)
	if err != nil {
		return nil, err
	}
	diff, err := settings.CheckPatch(ctx, expected, patch)
	if err != nil {
		return nil, err
	}
	version := diff.Version
	plan := newAgentPlan(agentapi.OpConfigSet, agentPlanTarget{Kind: "analysis-settings", Version: agentVersion(version)})
	plan.view.Before, plan.view.After = agentAnalysisSettingsValuesOf(diff.Before), agentAnalysisSettingsValuesOf(diff.After)
	plan.view.Extras["api_key"] = diff.KeySource
	changedOrNothing(plan, diff.Changed)
	plan.effect(effectAnalysis)
	if contains(diff.Changed, "llm.base_url") || contains(diff.Changed, "llm.model") {
		plan.effect(effectModelMoved)
	}
	if diff.KeySource != sessionanalysis.KeyNone && changesModelTarget(diff.Changed) {
		plan.effect("The API key in use (" + diff.KeySource + " key) will be sent to the new address in after.llm.base_url from then on, by every run and every connection test.")
	}
	plan.verify = "llmaudit config show --kind analysis-settings"
	plan.apply = func(ctx context.Context) (agentApplied, error) {
		view, err := settings.Patch(ctx, version, patch)
		return agentApplied{Version: agentVersion(view.UpdatedNS)}, err
	}
	return plan, nil
}

// changesModelTarget reports whether changed names a field that decides
// where model requests are sent.
func changesModelTarget(changed []string) bool {
	for _, field := range sessionanalysis.ModelTargetFields {
		if contains(changed, field) {
			return true
		}
	}
	return false
}

// ---- config.remove ----

var removableKinds = []string{"ua-rule", "content-rule", "group", "project", "member", "principal"}

func (handler *managementHandler) planConfigRemove(_ context.Context, request agentPlanRequest) (*agentPlan, error) {
	if err := checkWriteKind(request.Kind, removableKinds); err != nil {
		if contains(agentapi.WriteKinds, request.Kind) {
			return nil, fieldFailure("kind", request.Kind+" cannot be removed; restore the configuration file values with config.reset")
		}
		return nil, err
	}
	var plan *agentPlan
	var deleted any
	switch request.Kind {
	case "principal":
		org, err := handler.agentOrgWriter()
		if err != nil {
			return nil, err
		}
		kind, id, err := agentPrincipalID(request)
		if err != nil {
			return nil, err
		}
		expected, err := agentExpectedVersion(request, orgreport.AnyVersion)
		if err != nil {
			return nil, err
		}
		removed, err := org.CheckDeletePrincipal(kind, id, expected)
		if err != nil {
			return nil, err
		}
		version := removed.UpdatedAtNS
		deleted = agentOrgPrincipalOf(removed)
		plan = newAgentPlan(agentapi.OpConfigRemove, agentPlanTarget{Kind: "principal", ID: kind + ":" + formatAgentID(id), Version: agentVersion(version)})
		plan.apply = func(ctx context.Context) (agentApplied, error) {
			return agentApplied{}, org.DeletePrincipalIfVersion(ctx, kind, id, version)
		}
	default:
		id, err := agentNumericID(request)
		if err != nil {
			return nil, err
		}
		var version int64
		var remove func(context.Context) error
		switch request.Kind {
		case "ua-rule":
			rules, err := handler.agentUAWriter()
			if err != nil {
				return nil, err
			}
			expected, err := agentExpectedVersion(request, uaguard.AnyVersion)
			if err != nil {
				return nil, err
			}
			rule, err := rules.CheckDelete(id, expected)
			if err != nil {
				return nil, err
			}
			version, deleted = rule.UpdatedAtNS, agentUARuleView(rule)
			remove = func(ctx context.Context) error { return rules.DeleteIfVersion(ctx, id, version) }
		case "content-rule":
			policies, err := handler.agentContentWriter()
			if err != nil {
				return nil, err
			}
			expected, err := agentExpectedVersion(request, contentpolicy.AnyVersion)
			if err != nil {
				return nil, err
			}
			rule, err := policies.CheckDelete(id, expected)
			if err != nil {
				return nil, err
			}
			version, deleted = rule.UpdatedAtNS, agentContentRuleView(rule)
			remove = func(ctx context.Context) error { return policies.DeleteIfVersion(ctx, id, version) }
		default:
			org, err := handler.agentOrgWriter()
			if err != nil {
				return nil, err
			}
			expected, err := agentExpectedVersion(request, orgreport.AnyVersion)
			if err != nil {
				return nil, err
			}
			switch request.Kind {
			case "group":
				group, err := org.CheckDeleteGroup(id, expected)
				if err != nil {
					return nil, err
				}
				version, deleted = group.UpdatedAtNS, agentOrgGroupOf(group)
				remove = func(ctx context.Context) error { return org.DeleteGroupIfVersion(ctx, id, version) }
			case "project":
				project, err := org.CheckDeleteProject(id, expected)
				if err != nil {
					return nil, err
				}
				version, deleted = project.UpdatedAtNS, agentOrgProjectOf(project)
				remove = func(ctx context.Context) error { return org.DeleteProjectIfVersion(ctx, id, version) }
			default:
				member, err := org.CheckDeleteMember(id, expected)
				if err != nil {
					return nil, err
				}
				version, deleted = member.UpdatedAtNS, agentOrgMemberOf(member)
				remove = func(ctx context.Context) error { return org.DeleteMemberIfVersion(ctx, id, version) }
			}
		}
		plan = newAgentPlan(agentapi.OpConfigRemove, agentPlanTarget{Kind: request.Kind, ID: formatAgentID(id), Version: agentVersion(version)})
		plan.apply = func(ctx context.Context) (agentApplied, error) { return agentApplied{}, remove(ctx) }
	}
	plan.view.Before = deleted
	plan.view.Extras["deleted_object"] = deleted
	plan.untrusted = request.Kind != "member" && request.Kind != "principal"
	switch request.Kind {
	case "ua-rule", "content-rule":
		plan.effect(effectLiveRule)
		plan.verify = "llmaudit config show --kind " + request.Kind
	default:
		plan.effect(effectCatalog)
		plan.verify = "llmaudit config show --kind org"
	}
	plan.effect(effectDeleteOnly)
	switch request.Kind {
	case "member", "principal":
		plan.effect(effectIrreversible + ": the entry can be set again with config set (extras.deleted_object has its old value), as a new entry with a new version.")
	default:
		plan.effect(effectIrreversible + ": an object created again from extras.deleted_object is a new object, with a new id assigned by the server; anything that referred to the old id does not follow.")
	}
	return plan, nil
}

// ---- config.reset ----

func (handler *managementHandler) planConfigReset(ctx context.Context, request agentPlanRequest) (*agentPlan, error) {
	if err := checkWriteKind(request.Kind, []string{"weekly-settings", "analysis-settings"}); err != nil {
		return nil, err
	}
	if request.Kind == "weekly-settings" {
		org, err := handler.agentOrgWriter()
		if err != nil {
			return nil, err
		}
		diff, err := org.CheckResetSettings(ctx, orgreport.AnyVersion)
		if err != nil {
			return nil, err
		}
		version := diff.Version
		if !diff.Stored {
			return nil, nothingSaved("weekly-settings")
		}
		plan := newAgentPlan(agentapi.OpConfigReset, agentPlanTarget{Kind: "weekly-settings", Version: agentVersion(version)})
		plan.view.Before, plan.view.After = agentWeeklySettingsValuesOf(diff.Before), agentWeeklySettingsValuesOf(diff.After)
		plan.view.ChangedKeys = append([]string{}, diff.Changed...)
		plan.effect(resetEffect(len(diff.Changed) > 0, ""))
		if version == 0 {
			plan.effect(effectUnusableSaved)
		}
		if len(diff.Changed) > 0 {
			plan.effect(effectWeekly)
		}
		plan.verify = "llmaudit config show --kind weekly-settings"
		plan.apply = func(ctx context.Context) (agentApplied, error) {
			view, err := org.ResetSettingsIfVersion(ctx, version)
			return agentApplied{Version: agentVersion(view.UpdatedNS)}, err
		}
		return plan, nil
	}
	settings, err := handler.agentAnalysisSettingsWriter()
	if err != nil {
		return nil, err
	}
	diff, err := settings.CheckReset(ctx, sessionanalysis.AnyVersion)
	if err != nil {
		return nil, err
	}
	version := diff.Version
	if !diff.Stored {
		return nil, nothingSaved("analysis-settings")
	}
	plan := newAgentPlan(agentapi.OpConfigReset, agentPlanTarget{Kind: "analysis-settings", Version: agentVersion(version)})
	plan.view.Before, plan.view.After = agentAnalysisSettingsValuesOf(diff.Before), agentAnalysisSettingsValuesOf(diff.After)
	plan.view.Extras["api_key"] = map[string]string{"before": diff.BeforeKeySource, "after": diff.KeySource}
	changed := append([]string{}, diff.Changed...)
	// The saved key is dropped with the section: the key in use changes unless
	// none is in use before or after.
	keyChanges := diff.BeforeKeySource == sessionanalysis.KeySaved || diff.BeforeKeySource != diff.KeySource
	if keyChanges {
		changed = append(changed, "api_key")
	}
	plan.view.ChangedKeys = changed
	keyEffect := "No API key is in use before or after."
	switch {
	case keyChanges && diff.KeySource == sessionanalysis.KeyNone:
		keyEffect = "The API key in use (" + diff.BeforeKeySource + " key) is dropped; the configuration file has none, so the model is called without a key afterwards."
	case keyChanges:
		keyEffect = "The API key in use changes from the " + diff.BeforeKeySource + " key to the configuration file's key."
	case diff.KeySource != sessionanalysis.KeyNone:
		keyEffect = "The configuration file's API key stays in use."
	}
	plan.effect(resetEffect(len(diff.Changed) > 0, keyEffect))
	if version == 0 {
		plan.effect(effectUnusableSaved)
	}
	if len(diff.Changed) > 0 || keyChanges {
		plan.effect(effectAnalysis)
	}
	plan.verify = "llmaudit config show --kind analysis-settings"
	plan.apply = func(ctx context.Context) (agentApplied, error) {
		view, err := settings.ResetIfVersion(ctx, version)
		return agentApplied{Version: agentVersion(view.UpdatedNS)}, err
	}
	return plan, nil
}

// effectUnusableSaved is said by a reset of a stored section that can no
// longer be used (the file's values already apply, version "0"): the reset
// deletes it, as the web page's reset does.
const effectUnusableSaved = "A saved section is stored but can no longer be used, so the configuration file values already apply; applying deletes the stored section."

// nothingSaved refuses a reset of a section that has nothing saved: the
// configuration file's values already apply, and applying would change
// nothing.
func nothingSaved(kind string) *agentFailure {
	return &agentFailure{Code: agentapi.CodeInvalidArgument,
		Message: "nothing is saved for " + kind + ": the configuration file values already apply, so there is nothing to reset",
		Hint:    "Nothing to do. `llmaudit config show --kind " + kind + "` shows the values in effect (version \"0\" means they come from the configuration file).",
		Details: map[string]any{"field": "kind", "reason": "nothing_saved"}}
}

// resetEffect is the one sentence of a reset plan: what dropping the saved
// section does, for the state the plan shows. keyEffect is appended when
// given.
func resetEffect(valuesChange bool, keyEffect string) string {
	text := "Drops the saved settings: the configuration file values apply again (the source becomes the file, version \"0\")."
	if !valuesChange {
		text = "Drops the saved settings: their values equal the configuration file's, so no setting value changes; only the source becomes the file (version \"0\")."
	}
	if keyEffect != "" {
		text += " " + keyEffect
	}
	return text
}

// ---- config.clear-key ----

// planConfigClearKey plans clearing the analysis model's API key. Setting a
// key is not a plan: the user types it at a terminal and it never enters the
// agent's context. Clearing carries no value, but it removes one the agent
// cannot restore, so the user sees it and agrees before it happens. Once
// applied the key source is none, as when the web form's key field is
// emptied.
func (handler *managementHandler) planConfigClearKey(ctx context.Context, request agentPlanRequest) (*agentPlan, error) {
	if err := checkWriteKind(request.Kind, []string{"analysis-settings"}); err != nil {
		return nil, err
	}
	settings, err := handler.agentAnalysisSettingsWriter()
	if err != nil {
		return nil, err
	}
	diff, err := settings.CheckClearAPIKey(ctx, sessionanalysis.AnyVersion)
	if err != nil {
		return nil, err
	}
	version := diff.Version
	if diff.KeySource == sessionanalysis.KeyNone {
		// Applying would save the section with no key: from the file's values
		// to saved ones, a new version and nothing else. There is nothing to
		// clear, so there is no plan.
		return nil, &agentFailure{Code: agentapi.CodeInvalidArgument, Message: "no API key is in use: there is nothing to clear",
			Hint:    "Nothing to do. `llmaudit config show --kind analysis-settings` shows where the key comes from (api_key: none).",
			Details: map[string]any{"field": "api_key", "reason": "nothing_to_clear"}}
	}
	plan := newAgentPlan(agentapi.OpConfigClearKey, agentPlanTarget{Kind: "analysis-settings", Version: agentVersion(version)})
	plan.view.Before, plan.view.After = agentAnalysisSettingsValuesOf(diff.Before), agentAnalysisSettingsValuesOf(diff.After)
	plan.view.Extras["api_key"] = map[string]string{"before": diff.KeySource, "after": sessionanalysis.KeyNone}
	plan.view.ChangedKeys = []string{"api_key"}
	plan.effect("Removes the API key in use (" + diff.KeySource + " key): the model is called without a key from then on. " +
		"Only the user can set a key again, by typing it at a terminal with `llmaudit config set-key --kind analysis-settings`; " +
		"the configuration file's key comes back only with `llmaudit config reset --kind analysis-settings`.")
	plan.effect(effectIrreversible + ": the key's value is not kept anywhere the agent can reach.")
	if version == 0 {
		plan.effect("Nothing is saved yet: applying saves the settings in effect (the configuration file's values) without a key, so the source becomes saved with a new version; no other setting value changes.")
	}
	plan.effect(effectAnalysis)
	plan.verify = "llmaudit config show --kind analysis-settings"
	plan.apply = func(ctx context.Context) (agentApplied, error) {
		view, err := settings.ClearAPIKeyIfVersion(ctx, version)
		return agentApplied{Version: agentVersion(view.UpdatedNS)}, err
	}
	return plan, nil
}
