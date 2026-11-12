package orgreport

// ProjectKey identifies where a request's time and usage are booked: a
// positive project id, or one of the two unmatched buckets.
type ProjectKey int64

const (
	// ProjectUnattributed: the request carried a repository or working
	// directory, but no project rule matched it.
	ProjectUnattributed ProjectKey = -1
	// ProjectNoContext: the request carried no path or project signal at all
	// (chat-style clients, title requests without inheritance).
	ProjectNoContext ProjectKey = -2
)

// Principal classes (doc section 6.2).
const (
	ClassHuman   = "human"
	ClassService = "service"
)

// Agent roles as stored by insights in audit_analysis.agent_role.
const (
	roleMain       = "main"
	roleSubagent   = "subagent"
	roleCompaction = "compaction"
	roleTitle      = "title"
	roleReview     = "review"
	roleAuxiliary  = "auxiliary"
)

// sideRole reports a request that is not agent work of its own.
func sideRole(role string) bool {
	switch role {
	case roleCompaction, roleTitle, roleReview, roleAuxiliary:
		return true
	}
	return false
}

// Tokens are the four mutually exclusive usage buckets.
type Tokens struct {
	Uncached   int64 `json:"uncached"`
	CacheRead  int64 `json:"cache_read"`
	CacheWrite int64 `json:"cache_write"`
	Output     int64 `json:"output"`
}

// Total sums every bucket.
func (tokens Tokens) Total() int64 {
	return tokens.Uncached + tokens.CacheRead + tokens.CacheWrite + tokens.Output
}

func (tokens *Tokens) add(other Tokens) {
	tokens.Uncached += other.Uncached
	tokens.CacheRead += other.CacheRead
	tokens.CacheWrite += other.CacheWrite
	tokens.Output += other.Output
}

// Request is one audited request as the time engine sees it. The loader fills
// everything except Project, which attribution sets.
type Request struct {
	AuditID string
	StartNS int64
	EndNS   int64
	UserID  int64 // NewAPI user; 0 when the caller is unresolved
	TokenID int64
	Client  string // audit_analysis.agent_client
	Role    string // audit_analysis.agent_role
	// RootKey is the agent-tree root (agent_root_fpr) and NodeKey the agent
	// node, both as opaque strings; empty when insights found none.
	RootKey string
	NodeKey string
	// CallerKey is the caller scope (the API key fingerprint) as an opaque
	// string; empty when the request carried no key. Identity inheritance
	// never crosses it: two callers reusing one session id stay apart.
	CallerKey string
	// Inferred marks a session linked by the inferred session key (system
	// prompt fingerprint plus first user message) rather than a client id.
	Inferred bool
	// CacheWarm marks a cache-refresh request (pi cache warmer): usage only,
	// never active time (doc section 6.1).
	CacheWarm bool
	Tokens    Tokens
	CostUSD   float64
	Billed    bool
	// IdentityKey groups requests with the same extracted project identity;
	// empty means the request carried none.
	IdentityKey string
	Project     ProjectKey
}
