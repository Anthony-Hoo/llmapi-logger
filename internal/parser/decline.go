package parser

import "errors"

// ErrStreamResidueTooLarge is returned by a stream normalizer that declines a
// stream because what its fold cannot hold exceeds the residue limit
// (streamevidence.MaxResidueBytes). It lives here, beside the worker, so the
// worker can tell this decline from a normalization failure. Today the
// worker treats both alike: the parse is partial with normalization_failed
// and the raw bodies stay.
var ErrStreamResidueTooLarge = errors.New("parser: stream residue exceeds the limit")
