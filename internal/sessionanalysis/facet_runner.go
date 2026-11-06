package sessionanalysis

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// FacetAAD is the additional data binding a facet's text ciphertext to its key.
func FacetAAD(key []byte) ([]byte, error) {
	return security.AAD("session_facet", hex.EncodeToString(key))
}

// facetText is the encrypted part of a facet.
type facetText struct {
	Goal           string              `json:"goal,omitempty"`
	Instructions   []string            `json:"instructions,omitempty"`
	SkillCandidate string              `json:"skill_candidate,omitempty"`
	Evidence       map[string][]string `json:"evidence,omitempty"`
}

func encodeList(values any) string {
	encoded, err := json.Marshal(values)
	if err != nil || string(encoded) == "null" {
		return "[]"
	}
	return string(encoded)
}

// runFacets is the L1 stage (doc 24 section 7): every pack that has been
// quiet for l1_settle_hours and has no facet for its current text, prompt
// version and model goes to the local model, at most max_sessions_per_run
// per run and max_concurrency at a time. Model failures never fail the run.
func (runner *Runner) runFacets(ctx context.Context, run *storage.SessionAnalysisRun) error {
	options := runner.options
	if options.LLM == nil {
		return nil
	}
	settled := options.Now().Add(-time.Duration(options.Config.L1SettleHours) * time.Hour).UnixNano()
	limit := options.Config.LLM.MaxSessionsRun
	if limit <= 0 {
		limit = 300
	}
	due, err := options.Store.ListFacetCandidates(ctx, settled, PromptVersion, options.LLM.Model(), limit)
	if err != nil {
		return err
	}
	run.L1Candidates = int64(len(due))
	concurrency := options.Config.LLM.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 1
	}
	slots := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wait sync.WaitGroup
	for _, pack := range due {
		if ctx.Err() != nil {
			break
		}
		slots <- struct{}{}
		wait.Add(1)
		go func(pack storage.SessionPack) {
			defer wait.Done()
			defer func() { <-slots }()
			facet := runner.facetOne(ctx, pack)
			saveContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			saveErr := options.Store.SaveSessionFacet(saveContext, facet.row, facet.fprs)
			mu.Lock()
			defer mu.Unlock()
			run.L1InputTokens += facet.row.InputTokens
			run.L1OutputToks += facet.row.OutputTokens
			switch {
			case saveErr != nil || facet.row.Status == FacetFailed:
				run.L1Failed++
			case facet.row.Status == FacetInvalid:
				run.L1Invalid++
			default:
				run.L1OK++
			}
		}(pack)
	}
	wait.Wait()
	return ctx.Err()
}

type facetResult struct {
	row  storage.SessionFacet
	fprs []storage.SessionTextFPR
}

// facetOne decrypts one pack, calls the model, retries once on output that
// is not a JSON object, and returns the row to store.
func (runner *Runner) facetOne(ctx context.Context, pack storage.SessionPack) facetResult {
	options := runner.options
	row := storage.SessionFacet{
		SessionKey: pack.SessionKey, Kind: pack.Kind, APIKeyFPR: pack.APIKeyFPR, NewAPITokenID: pack.NewAPITokenID,
		LastNS: pack.LastNS, PackHash: pack.PackHash, PromptVersion: PromptVersion, Model: options.LLM.Model(),
		Status: FacetFailed, CreatedAtNS: options.Now().UnixNano(),
	}
	aad, err := PackAAD(pack.SessionKey)
	if err != nil {
		return facetResult{row: row}
	}
	plaintext, err := options.Cipher.Decrypt(aad, pack.PackEnc)
	if err != nil {
		return facetResult{row: row}
	}
	text := string(plaintext)
	clear(plaintext)
	refs := map[string]string{}
	_ = json.Unmarshal([]byte(pack.RefMap), &refs)
	digest := pack.Kind == storage.PackKindChatDigest
	messages := FacetMessages(text, digest)
	schema := FacetSchema(digest)
	timeout := time.Duration(options.Config.LLM.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	var facet Facet
	parsed := false
	for attempt := 0; attempt < 2 && !parsed; attempt++ {
		callContext, cancel := context.WithTimeout(ctx, timeout)
		completion, err := options.LLM.Complete(callContext, messages, schema)
		cancel()
		row.InputTokens += completion.InputTokens
		row.OutputTokens += completion.OutputTokens
		row.LatencyMS += completion.Latency.Milliseconds()
		if err != nil {
			return facetResult{row: row} // transient: retried by a later run
		}
		facet, err = ParseFacet(completion.Content, digest, refs, options.Vocabulary)
		parsed = err == nil
	}
	if !parsed {
		row.Status = FacetInvalid
		return facetResult{row: row}
	}
	row.Status = FacetOK
	row.TaskType, row.Outcome, row.Collaboration, row.WorkRelevance = facet.TaskType, facet.Outcome, facet.Collaboration, facet.WorkRelevance
	row.Friction = encodeList(facet.Friction)
	row.Items = encodeList(facet.Items)
	row.InvalidFields = encodeList(facet.InvalidFields)
	secret, err := json.Marshal(facetText{Goal: facet.Goal, Instructions: facet.Instructions, SkillCandidate: facet.SkillCandidate, Evidence: facet.Evidence})
	if err != nil {
		row.Status = FacetFailed
		return facetResult{row: row}
	}
	textAAD, err := FacetAAD(pack.SessionKey)
	if err == nil {
		row.TextEnc, err = options.Cipher.Encrypt(textAAD, secret)
	}
	clear(secret)
	if err != nil {
		row.Status = FacetFailed
		return facetResult{row: row}
	}
	fprs := make([]storage.SessionTextFPR, 0, len(facet.Instructions)+1)
	for _, instruction := range facet.Instructions {
		if tag := instructionFingerprint(options.Fingerprints, instruction); tag != nil {
			fprs = append(fprs, storage.SessionTextFPR{Source: storage.TextSourceFacetInstruction, FPR: tag, APIKeyFPR: pack.APIKeyFPR, SeenAtNS: pack.LastNS})
		}
	}
	if tag := instructionFingerprint(options.Fingerprints, facet.SkillCandidate); tag != nil {
		fprs = append(fprs, storage.SessionTextFPR{Source: storage.TextSourceFacetSkill, FPR: tag, APIKeyFPR: pack.APIKeyFPR, SeenAtNS: pack.LastNS})
	}
	return facetResult{row: row, fprs: dedupeFPRs(fprs)}
}

// instructionFingerprint tags one whole instruction, normalized like user
// sentences so an instruction a user typed and one the model extracted match.
func instructionFingerprint(fp Fingerprinter, text string) []byte {
	normalized := normalizeSentence(text)
	if fp == nil || len([]rune(normalized)) < minSentenceRunes {
		return nil
	}
	return fp.Fingerprint(domainSentence, []byte(normalized))
}

func dedupeFPRs(fprs []storage.SessionTextFPR) []storage.SessionTextFPR {
	seen := map[string]bool{}
	out := make([]storage.SessionTextFPR, 0, len(fprs))
	for _, fpr := range fprs {
		key := fpr.Source + string(fpr.FPR)
		if !seen[key] {
			seen[key] = true
			out = append(out, fpr)
		}
	}
	return out
}
