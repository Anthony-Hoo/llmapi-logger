package archive

import (
	"net/url"
	"strings"

	"llmapi-logger/internal/agentapi"
	"llmapi-logger/internal/headerblock"
	"llmapi-logger/internal/query"
)

// CredentialFingerprinter computes value_fpr (D.4):
// HMAC-SHA-256(K_fpr, "llmapi-logger/archive-credential-value/v1\x00" || value)
// over the raw value bytes, for every value including an empty one.
// security.ArchiveKeys implements it.
type CredentialFingerprinter interface {
	CredentialFingerprint(value []byte) [32]byte
}

// OmittedCredential is the value_omitted reason of a projected credential.
const OmittedCredential = agentapi.OmittedCredential

// ProjectedValue is one Header, Trailer or User-Agent value in archived form
// (D.3): either the value itself, or, for a credential, its byte length and
// keyed fingerprint. The two forms are exclusive.
type ProjectedValue struct {
	Omitted     bool
	Value       string
	Length      int64
	Fingerprint [32]byte
}

// RequestURI is the projected Request-URI of D.3 (Q3 甲): the bytes before
// the first '?', whether there is a '?', and the query split at every '&'
// with empty segments kept. Only credential segments lose bytes.
type RequestURI struct {
	Path     string
	HasQuery bool
	Segments []QuerySegment
}

// QuerySegment is one '&'-separated query segment. A non-credential segment
// keeps its raw bytes in Raw. A credential segment keeps the raw bytes of
// its name (before the first '='), whether it had a '=', and the length and
// fingerprint of its value: the percent-decoded value, or the raw value
// bytes when decoding fails.
type QuerySegment struct {
	Credential  bool
	Raw         string
	RawName     string
	HasEquals   bool
	Length      int64
	Fingerprint [32]byte
}

// ProjectValue projects one value under its name with agentapi.IsCredential,
// the masking rule of the Agent facade (D.1).
func ProjectValue(fingerprinter CredentialFingerprinter, name string, value []byte) ProjectedValue {
	if agentapi.IsCredential(name, string(value)) {
		return ProjectedValue{Omitted: true, Length: int64(len(value)), Fingerprint: fingerprinter.CredentialFingerprint(value)}
	}
	return ProjectedValue{Value: string(value)}
}

// ProjectHeaders projects the flat header list headerblock.Expand returns,
// value by value, keeping its order.
func ProjectHeaders(fingerprinter CredentialFingerprinter, values []headerblock.Value) []HeaderValue {
	projected := make([]HeaderValue, 0, len(values))
	for _, value := range values {
		projected = append(projected, HeaderValue{
			Stage: value.Stage, Kind: value.Kind, Name: value.Name, ValueIndex: int64(value.ValueIndex),
			Value: ProjectValue(fingerprinter, value.Name, value.Value),
		})
	}
	return projected
}

// ProjectUserAgent projects the opened user_agent_enc values under the name
// "User-Agent". nil (user_agent_enc NULL) stays nil.
func ProjectUserAgent(fingerprinter CredentialFingerprinter, values []string) []ProjectedValue {
	if values == nil {
		return nil
	}
	projected := make([]ProjectedValue, 0, len(values))
	for _, value := range values {
		projected = append(projected, ProjectValue(fingerprinter, "User-Agent", []byte(value)))
	}
	return projected
}

// ProjectRequestURI projects the opened request_uri_enc (D.3). Each segment
// is judged by agentapi.IsCredential on its name and value, each decoded on
// its own with url.QueryUnescape (the rule Go's query parser applies, so '+'
// is a space) and taken as raw bytes when it does not decode. '#' and ';' are
// not special.
func ProjectRequestURI(fingerprinter CredentialFingerprinter, raw []byte) RequestURI {
	text := string(raw)
	path, query, hasQuery := strings.Cut(text, "?")
	projected := RequestURI{Path: path, HasQuery: hasQuery, Segments: []QuerySegment{}}
	if !hasQuery {
		return projected
	}
	for _, segment := range strings.Split(query, "&") {
		rawName, rawValue, hasEquals := strings.Cut(segment, "=")
		name := decodeQueryPart(rawName)
		value := decodeQueryPart(rawValue)
		if !agentapi.IsCredential(name, value) {
			projected.Segments = append(projected.Segments, QuerySegment{Raw: segment})
			continue
		}
		projected.Segments = append(projected.Segments, QuerySegment{
			Credential: true, RawName: rawName, HasEquals: hasEquals,
			Length: int64(len(value)), Fingerprint: fingerprinter.CredentialFingerprint([]byte(value)),
		})
	}
	return projected
}

func decodeQueryPart(raw string) string {
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return raw
	}
	return decoded
}

// ProjectedDetail is a query.Detail in archived form. Detail has RequestURI
// empty, Headers nil and Audit.UserAgent nil; the projected forms are in the
// other fields. A header's ValueLength is its projected Length for a
// credential and the length of Value otherwise.
type ProjectedDetail struct {
	Detail     query.Detail
	RequestURI RequestURI
	Headers    []HeaderValue
	UserAgent  *ProjectedValue
}

// ProjectedSummary is a query.AuditSummary in archived form: Summary has
// UserAgent nil, and the projected User-Agent is in UserAgent.
type ProjectedSummary struct {
	Summary   query.AuditSummary
	UserAgent *ProjectedValue
}

// ProjectDetail projects the hot side's Detail as the archive stores it
// (D.5 item 3, J.3), with Audit.ConversationTurns cleared as ProjectSummary
// does. The input is not changed.
func ProjectDetail(fingerprinter CredentialFingerprinter, detail query.Detail) ProjectedDetail {
	projected := ProjectedDetail{
		RequestURI: ProjectRequestURI(fingerprinter, []byte(detail.RequestURI)),
		Headers:    make([]HeaderValue, 0, len(detail.Headers)),
	}
	for _, header := range detail.Headers {
		projected.Headers = append(projected.Headers, HeaderValue{
			Stage: header.Stage, Kind: header.Kind, Name: header.Name, ValueIndex: int64(header.ValueIndex),
			Value: ProjectValue(fingerprinter, header.Name, []byte(header.Value)),
		})
	}
	summary := ProjectSummary(fingerprinter, detail.Audit)
	projected.UserAgent = summary.UserAgent
	projected.Detail = detail
	projected.Detail.Audit = summary.Summary
	projected.Detail.RequestURI = ""
	projected.Detail.Headers = nil
	return projected
}

// ProjectSummary projects the User-Agent of one list row. It also clears
// ConversationTurns, which J.3 leaves out of the comparison: it is a
// query-time count over the hot conversation (A.3) that an archive cannot
// reproduce.
func ProjectSummary(fingerprinter CredentialFingerprinter, summary query.AuditSummary) ProjectedSummary {
	projected := ProjectedSummary{Summary: summary}
	if summary.UserAgent != nil {
		value := ProjectValue(fingerprinter, "User-Agent", []byte(*summary.UserAgent))
		projected.UserAgent = &value
	}
	projected.Summary.UserAgent = nil
	projected.Summary.ConversationTurns = nil
	return projected
}

// KnownKeyFingerprints returns the value_fpr a known key has in the two
// forms a credential value takes (D.4): the key itself, as in X-Api-Key,
// X-Goog-Api-Key or ?key=, and "Bearer " followed by the key, as in
// Authorization. The third candidate of the audit-archive fpr subcommand,
// the normalised key compared with audit_records.api_key_fpr, uses the
// separate credential fingerprint key of internal/security.
func KnownKeyFingerprints(fingerprinter CredentialFingerprinter, key []byte) (raw, bearer [32]byte) {
	return fingerprinter.CredentialFingerprint(key), fingerprinter.CredentialFingerprint(append([]byte("Bearer "), key...))
}
