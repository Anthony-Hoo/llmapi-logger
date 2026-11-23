package agentaccess

import "time"

// The exchange limiter's numbers, for the tests that hold it to them.
const (
	ExchangeFailureLimit = exchangeFailureLimit
	ExchangeInFlightCap  = exchangeInFlightCap
)

// SetReplayRetry shortens the background retry of a replay revocation for
// tests: the first wait, the largest wait and how long it keeps trying.
func SetReplayRetry(service *Service, first, max, total time.Duration) {
	service.replayRetry = replayRetry{first: first, max: max, total: total}
}
