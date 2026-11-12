package sessionanalysis

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"llmapi-logger/internal/query"
	"llmapi-logger/internal/storage"
)

// FacetStore is the storage surface of the facet and calibration API.
type FacetStore interface {
	LoadSessionFacet(ctx context.Context, sessionKey []byte) (storage.SessionFacet, error)
	SaveFacetCalibration(ctx context.Context, calibration storage.FacetCalibration) error
	LatestFacetCalibration(ctx context.Context, promptVersion, model string) (storage.FacetCalibration, error)
}

// EvidenceRef is one evidence label and the audit it points to.
type EvidenceRef struct {
	Label   string `json:"label"`
	AuditID string `json:"audit_id,omitempty"`
}

// FacetResponse is GET /api/v1/session-analysis/sessions/{id}/facet.
type FacetResponse struct {
	SessionID      string                   `json:"session_id"`
	PackID         string                   `json:"pack_id"`
	Kind           string                   `json:"kind"`
	Status         string                   `json:"status"`
	Model          string                   `json:"model"`
	PromptVersion  string                   `json:"prompt_version"`
	CreatedNS      int64                    `json:"created_ns,string"`
	TaskType       string                   `json:"task_type,omitempty"`
	Outcome        string                   `json:"outcome,omitempty"`
	Collaboration  string                   `json:"collaboration,omitempty"`
	WorkRelevance  string                   `json:"work_relevance,omitempty"`
	Friction       []string                 `json:"friction"`
	Items          []DigestFacetItem        `json:"items"`
	InvalidFields  []string                 `json:"invalid_fields"`
	Goal           string                   `json:"goal,omitempty"`
	Instructions   []string                 `json:"instructions"`
	SkillCandidate string                   `json:"skill_candidate,omitempty"`
	Evidence       map[string][]EvidenceRef `json:"evidence"`
	HiddenFields   []string                 `json:"hidden_fields"`
}

// Facet decrypts the facet of one session (its own, or its chat digest's)
// and records the view.
func (service *QueryService) Facet(ctx context.Context, sessionID string, scope *query.Scope, viewer Viewer) (FacetResponse, error) {
	if service.facets == nil {
		return FacetResponse{}, query.ErrNotFound
	}
	key, err := ParseSessionID(sessionID)
	if err != nil {
		return FacetResponse{}, err
	}
	facet, err := service.facets.LoadSessionFacet(ctx, key)
	if errors.Is(err, sql.ErrNoRows) {
		return FacetResponse{}, query.ErrNotFound
	}
	if err != nil {
		return FacetResponse{}, err
	}
	if !ownedBy(scope, facet.APIKeyFPR, facet.NewAPITokenID) {
		return FacetResponse{}, query.ErrNotFound
	}
	response := FacetResponse{
		SessionID: sessionID, PackID: hex.EncodeToString(facet.SessionKey), Kind: facet.Kind, Status: facet.Status,
		Model: facet.Model, PromptVersion: facet.PromptVersion, CreatedNS: facet.CreatedAtNS,
		TaskType: facet.TaskType, Outcome: facet.Outcome, Collaboration: facet.Collaboration, WorkRelevance: facet.WorkRelevance,
		Friction: []string{}, Items: []DigestFacetItem{}, InvalidFields: []string{}, Instructions: []string{},
		Evidence: map[string][]EvidenceRef{}, HiddenFields: service.hiddenFields(ctx, facet.PromptVersion, facet.Model),
	}
	_ = json.Unmarshal([]byte(facet.Friction), &response.Friction)
	_ = json.Unmarshal([]byte(facet.Items), &response.Items)
	_ = json.Unmarshal([]byte(facet.InvalidFields), &response.InvalidFields)
	if scope == nil {
		// Work relevance is a compliance conclusion (doc 24 sections 9 and 10):
		// only the owner sees it until the review role and shadow run exist.
		response.WorkRelevance = ""
		for index := range response.Items {
			response.Items[index].WorkRelevance = ""
		}
	}
	if len(facet.TextEnc) != 0 {
		aad, err := FacetAAD(facet.SessionKey)
		if err != nil {
			return FacetResponse{}, query.ErrIntegrity
		}
		plaintext, err := service.cipher.Decrypt(aad, facet.TextEnc)
		if err != nil {
			return FacetResponse{}, query.ErrIntegrity
		}
		var text facetText
		decodeErr := json.Unmarshal(plaintext, &text)
		clear(plaintext)
		if decodeErr != nil {
			return FacetResponse{}, query.ErrIntegrity
		}
		response.Goal, response.SkillCandidate = text.Goal, text.SkillCandidate
		if text.Instructions != nil {
			response.Instructions = text.Instructions
		}
		refs := map[string]string{}
		if pack, err := service.store.LoadSessionPack(ctx, facet.SessionKey); err == nil {
			_ = json.Unmarshal([]byte(pack.RefMap), &refs)
		}
		for field, labels := range text.Evidence {
			for _, label := range labels {
				response.Evidence[field] = append(response.Evidence[field], EvidenceRef{Label: label, AuditID: refs[label]})
			}
		}
	}
	if err := service.store.RecordAnalysisView(ctx, storage.AnalysisView{
		AtNS: service.now().UnixNano(), ViewerRole: viewer.Role, ViewerUserID: viewer.UserID, ViewerTokenID: viewer.TokenID,
		Resource: "facet", SessionKey: key,
	}); err != nil {
		return FacetResponse{}, err
	}
	return response, nil
}

// CalibrationLabel is one human label of a session (doc 24 section 7.3).
// Empty fields are not compared.
type CalibrationLabel struct {
	SessionID     string   `json:"session_id"`
	TaskType      string   `json:"task_type,omitempty"`
	Outcome       string   `json:"outcome,omitempty"`
	Collaboration string   `json:"collaboration,omitempty"`
	WorkRelevance string   `json:"work_relevance,omitempty"`
	Friction      []string `json:"friction,omitempty"`
}

// CalibrationResult is the per-field agreement of one calibration.
type CalibrationResult struct {
	PromptVersion string             `json:"prompt_version"`
	Model         string             `json:"model"`
	Labels        int                `json:"labels"`
	Samples       int64              `json:"samples"`
	Compared      map[string]int64   `json:"compared"`
	Agreement     map[string]float64 `json:"agreement"`
	HiddenFields  []string           `json:"hidden_fields"`
	CreatedNS     int64              `json:"created_ns,string"`
}

// Calibration thresholds: a field below the bar is hidden from reports once
// at least minCalibrationSamples labels compared it.
const (
	calibrationBar        = 0.8
	minCalibrationSamples = 20
	maxCalibrationLabels  = 1000
)

// Calibrate compares human labels with the stored facets of the current
// prompt version and model and stores the per-field agreement.
func (service *QueryService) Calibrate(ctx context.Context, labels []CalibrationLabel) (CalibrationResult, error) {
	if service.facets == nil || service.modelName() == "" {
		return CalibrationResult{}, invalid("the local model is not enabled")
	}
	if len(labels) == 0 || len(labels) > maxCalibrationLabels {
		return CalibrationResult{}, invalid("between 1 and 1000 labels are required")
	}
	compared := map[string]int64{}
	agreed := map[string]int64{}
	result := CalibrationResult{PromptVersion: PromptVersion, Model: service.modelName(), Labels: len(labels)}
	for _, label := range labels {
		key, err := ParseSessionID(label.SessionID)
		if err != nil {
			return CalibrationResult{}, err
		}
		for field, value := range map[string]string{"task_type": label.TaskType, "outcome": label.Outcome, "collaboration": label.Collaboration, "work_relevance": label.WorkRelevance} {
			if value == "" {
				continue
			}
			if !contains(enumFor(field), value) {
				return CalibrationResult{}, invalid("unknown label value for " + field)
			}
		}
		for _, value := range label.Friction {
			if !contains(FrictionKinds, value) {
				return CalibrationResult{}, invalid("unknown friction label")
			}
		}
		facet, err := service.facets.LoadSessionFacet(ctx, key)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return CalibrationResult{}, err
		}
		if facet.Status != FacetOK || facet.Kind != storage.PackKindSession || facet.PromptVersion != PromptVersion || facet.Model != service.modelName() {
			continue
		}
		result.Samples++
		compare := func(field, want, got string) {
			if want == "" {
				return
			}
			compared[field]++
			if want == got {
				agreed[field]++
			}
		}
		compare("task_type", label.TaskType, facet.TaskType)
		compare("outcome", label.Outcome, facet.Outcome)
		compare("collaboration", label.Collaboration, facet.Collaboration)
		compare("work_relevance", label.WorkRelevance, facet.WorkRelevance)
		if label.Friction != nil {
			var got []string
			_ = json.Unmarshal([]byte(facet.Friction), &got)
			compared["friction"]++
			if sameSet(label.Friction, got) {
				agreed["friction"]++
			}
		}
	}
	result.Compared = compared
	result.Agreement = map[string]float64{}
	for field, count := range compared {
		result.Agreement[field] = float64(agreed[field]) / float64(count)
	}
	result.HiddenFields = hiddenFrom(result.Agreement, compared)
	result.CreatedNS = service.now().UnixNano()
	encoded, err := json.Marshal(struct {
		Agreement map[string]float64 `json:"agreement"`
		Compared  map[string]int64   `json:"compared"`
	}{result.Agreement, compared})
	if err != nil {
		return CalibrationResult{}, err
	}
	if err := service.facets.SaveFacetCalibration(ctx, storage.FacetCalibration{
		CreatedAtNS: result.CreatedNS, PromptVersion: PromptVersion, Model: service.modelName(), Samples: result.Samples, Agreement: string(encoded),
	}); err != nil {
		return CalibrationResult{}, err
	}
	return result, nil
}

func enumFor(field string) []string {
	switch field {
	case "task_type":
		return TaskTypes
	case "outcome":
		return Outcomes
	case "collaboration":
		return Collaborations
	default:
		return WorkRelevances
	}
}

func sameSet(left, right []string) bool {
	set := map[string]bool{}
	for _, value := range left {
		set[value] = true
	}
	other := map[string]bool{}
	for _, value := range right {
		other[value] = true
	}
	if len(set) != len(other) {
		return false
	}
	for value := range set {
		if !other[value] {
			return false
		}
	}
	return true
}

func hiddenFrom(agreement map[string]float64, compared map[string]int64) []string {
	hidden := make([]string, 0)
	for field, rate := range agreement {
		if compared[field] >= minCalibrationSamples && rate < calibrationBar {
			hidden = append(hidden, field)
		}
	}
	sort.Strings(hidden)
	return hidden
}

// hiddenFields returns the fields the latest calibration of one prompt
// version and model put below the bar.
func (service *QueryService) hiddenFields(ctx context.Context, promptVersion, model string) []string {
	if service.facets == nil {
		return []string{}
	}
	calibration, err := service.facets.LatestFacetCalibration(ctx, promptVersion, model)
	if err != nil {
		return []string{}
	}
	var stored struct {
		Agreement map[string]float64 `json:"agreement"`
		Compared  map[string]int64   `json:"compared"`
	}
	if json.Unmarshal([]byte(calibration.Agreement), &stored) != nil {
		return []string{}
	}
	return hiddenFrom(stored.Agreement, stored.Compared)
}

// latestCalibration summarizes the newest calibration for the overview.
func (service *QueryService) latestCalibration(ctx context.Context) *CalibrationResult {
	if service.facets == nil || service.modelName() == "" {
		return nil
	}
	calibration, err := service.facets.LatestFacetCalibration(ctx, PromptVersion, service.modelName())
	if err != nil {
		return nil
	}
	var stored struct {
		Agreement map[string]float64 `json:"agreement"`
		Compared  map[string]int64   `json:"compared"`
	}
	if json.Unmarshal([]byte(calibration.Agreement), &stored) != nil {
		return nil
	}
	return &CalibrationResult{
		PromptVersion: calibration.PromptVersion, Model: calibration.Model, Samples: calibration.Samples,
		Compared: stored.Compared, Agreement: stored.Agreement, HiddenFields: hiddenFrom(stored.Agreement, stored.Compared),
		CreatedNS: calibration.CreatedAtNS,
	}
}
