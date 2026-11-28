//go:build race

package integration_test

// archiveRaceBuild is true in a build with the race detector: see
// TestArchiveReadEquivalenceCatalogue for what it leaves out.
const archiveRaceBuild = true
