package orgreport

// SnapshotStore persists frozen weekly snapshots (M4).
type SnapshotStore interface{}

// snapshotJob guards the weekly snapshot goroutine (M4).
type snapshotJob struct{}
