package query

import (
	"context"
	"encoding/json"
	"errors"

	"llmapi-logger/internal/auditmodel"
	"llmapi-logger/internal/parser"
)

// ReconstructBodies adapts verified turn reconstruction to the insights
// backfill (parser.Reconstructor). It returns the rebuilt provider request and,
// for a non-stream response, the rebuilt response JSON. A stream response only
// has its envelope summary and aggregated messages, so those stand in for it.
func (service *Service) ReconstructBodies(ctx context.Context, auditID string) (parser.Reconstruction, error) {
	reconstructed, err := service.ReconstructTurn(ctx, auditID)
	if errors.Is(err, ErrNoTurnGraph) || errors.Is(err, ErrNotFound) {
		return parser.Reconstruction{}, parser.ErrReconstructionUnavailable
	}
	if err != nil {
		return parser.Reconstruction{}, err
	}
	var result parser.Reconstruction
	if reconstructed.Request != nil {
		if result.Request, err = json.Marshal(reconstructed.Request); err != nil {
			return parser.Reconstruction{}, err
		}
	}
	if reconstructed.Turn.ResponseLayout == auditmodel.LayoutOpenAIStreamResponse {
		result.ResponseIsStream = true
		result.Conversation = reconstructed.Conversation
		encoded, err := json.Marshal(reconstructed.Response)
		if err != nil {
			return parser.Reconstruction{}, err
		}
		var envelope struct {
			Summary struct {
				Usage struct {
					Input  *int64
					Output *int64
					Total  *int64
				}
			}
		}
		if err := json.Unmarshal(encoded, &envelope); err == nil {
			result.StreamUsage = parser.Usage{Input: envelope.Summary.Usage.Input, Output: envelope.Summary.Usage.Output, Total: envelope.Summary.Usage.Total}
		}
		return result, nil
	}
	if reconstructed.Response != nil {
		if result.Response, err = json.Marshal(reconstructed.Response); err != nil {
			return parser.Reconstruction{}, err
		}
	}
	return result, nil
}
