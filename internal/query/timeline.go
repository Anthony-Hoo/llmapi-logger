package query

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"llmapi-logger/internal/bodycodec"
	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
	"llmapi-logger/internal/streamtimeline"
)

const maxTimelinePoints = 100_000

func (service *Service) Timeline(ctx context.Context, auditID string, side Side) (StreamTimeline, error) {
	if ctx == nil {
		return StreamTimeline{}, invalid("nil context")
	}
	if err := validateAuditID(auditID); err != nil {
		return StreamTimeline{}, err
	}
	stage, _, err := service.selectRawBody(ctx, auditID, side)
	if errors.Is(err, sql.ErrNoRows) {
		return StreamTimeline{}, ErrNotFound
	}
	if err != nil {
		return StreamTimeline{}, err
	}
	stored, err := service.store.QueryStreamTimeline(ctx, auditID, stage)
	if errors.Is(err, sql.ErrNoRows) {
		return StreamTimeline{}, ErrNotFound
	}
	if err != nil {
		return StreamTimeline{}, fmt.Errorf("query: read stream timeline: %w", err)
	}
	if stored.EventCount <= 0 || stored.PlaintextLength <= 0 || len(stored.DataEnc) == 0 {
		return StreamTimeline{}, ErrIntegrity
	}
	aad, err := security.AAD(auditID, "stream_timeline_v1", stored.Stage, stored.Compression)
	if err != nil {
		return StreamTimeline{}, ErrIntegrity
	}
	encoded, err := service.cipher.Decrypt(aad, stored.DataEnc)
	if err != nil {
		return StreamTimeline{}, ErrIntegrity
	}
	plaintext, err := bodycodec.Decode(encoded, stored.Compression, int(stored.PlaintextLength))
	clear(encoded)
	if err != nil {
		return StreamTimeline{}, ErrIntegrity
	}
	defer clear(plaintext)
	return timelineFromPlaintext(stored, plaintext)
}

// timelineFromPlaintext is Timeline after decryption and decompression: it
// decodes and checks the points against the stored timeline row. DataEnc and
// Compression of stored are not read, and plaintext is not kept.
func timelineFromPlaintext(stored storage.StoredStreamTimeline, plaintext []byte) (StreamTimeline, error) {
	if stored.EventCount <= 0 || stored.PlaintextLength <= 0 || int64(len(plaintext)) != stored.PlaintextLength {
		return StreamTimeline{}, ErrIntegrity
	}
	points, err := streamtimeline.Decode(plaintext, maxTimelinePoints)
	if err != nil || len(points) == 0 || len(points) > maxTimelinePoints || int64(len(points)) > stored.EventCount {
		return StreamTimeline{}, ErrIntegrity
	}
	if stored.Complete && (stored.EventCount > maxTimelinePoints || int64(len(points)) != stored.EventCount) {
		return StreamTimeline{}, ErrIntegrity
	}
	if !stored.Complete && stored.EventCount > int64(len(points)) && len(points) != maxTimelinePoints {
		return StreamTimeline{}, ErrIntegrity
	}
	if stored.FirstEventAtNS == nil || stored.LastEventAtNS == nil ||
		points[0].AtNS != *stored.FirstEventAtNS || points[len(points)-1].AtNS > *stored.LastEventAtNS ||
		points[len(points)-1].Offset > stored.ObservedLength {
		return StreamTimeline{}, ErrIntegrity
	}
	if stored.Complete && points[len(points)-1].AtNS != *stored.LastEventAtNS {
		return StreamTimeline{}, ErrIntegrity
	}
	result := StreamTimeline{
		Stage: stored.Stage, ObservedLength: stored.ObservedLength,
		EventCount: stored.EventCount, FirstEventAtNS: stored.FirstEventAtNS,
		LastEventAtNS: stored.LastEventAtNS, Complete: stored.Complete,
		Points: make([]TimelinePoint, 0, len(points)),
	}
	for _, point := range points {
		result.Points = append(result.Points, TimelinePoint{Offset: point.Offset, AtNS: point.AtNS})
	}
	return result, nil
}
