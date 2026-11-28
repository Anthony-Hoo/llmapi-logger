package storage

import "testing"

// Every deferral reason the catalog's CHECK accepts passes the validator,
// export_failed included, and nothing else does.
func TestArchiveDeferredReasons(t *testing.T) {
	for _, reason := range []string{ArchiveDeferredOpen, ArchiveDeferredParsePending, ArchiveDeferredCallerPending,
		ArchiveDeferredIntegrityFailed, ArchiveDeferredExportFailed} {
		if err := ValidateArchiveDeferred(ArchiveDeferred{AuditID: "a", Reason: reason, FirstSeenAtNS: 1, LastCheckedAtNS: 1}); err != nil {
			t.Fatalf("%s: %v", reason, err)
		}
	}
	for _, reason := range []string{"", "other", "timeline", "not_found"} {
		if err := ValidateArchiveDeferred(ArchiveDeferred{AuditID: "a", Reason: reason, FirstSeenAtNS: 1, LastCheckedAtNS: 1}); err == nil {
			t.Fatalf("reason %q accepted", reason)
		}
	}
}
