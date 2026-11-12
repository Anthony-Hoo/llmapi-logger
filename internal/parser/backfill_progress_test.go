package parser

import "testing"

func TestBackfillProgressCoverage(t *testing.T) {
	var progress backfillProgress
	if progress.covered(10, 0) {
		t.Fatal("covered before any pass")
	}
	// A pass begins at 100 and works through candidates oldest first.
	progress.begin(100)
	progress.advance(5)
	if progress.covered(10, 50) {
		t.Fatal("covered before the cursor reached the week end")
	}
	progress.advance(12)
	if !progress.covered(10, 50) {
		t.Fatal("not covered once the cursor passed the week end")
	}
	if progress.covered(10, 150) {
		t.Fatal("a pass that began too early counts")
	}
	// A second begin while the pass runs does not restart it.
	progress.begin(120)
	if !progress.covered(10, 100) {
		t.Fatal("begin restarted a running pass")
	}
	progress.complete()
	if !progress.covered(1<<62, 100) {
		t.Fatal("a completed pass does not cover everything")
	}
	// The next pass starts from scratch; the completed one still answers for
	// its own start time.
	progress.begin(200)
	if progress.covered(10, 150) {
		t.Fatal("a new pass covers before reaching the week end")
	}
	if !progress.covered(10, 100) {
		t.Fatal("the completed pass was forgotten")
	}
	progress.advance(30)
	if !progress.covered(10, 150) {
		t.Fatal("the new pass does not cover once past the week end")
	}
}
