package insights

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"llmapi-logger/internal/security"
	"llmapi-logger/internal/storage"
)

// CompactDetailStore is optional so imported SQLite evidence remains readable.
// Implementations must insert new objects and the row in one transaction, and
// retain every ancestor reachable from a live row during garbage collection.
type CompactDetailStore interface {
	LoadAnalysisDetailChain(context.Context, []byte, int) ([]storage.AnalysisDetailObject, error)
	ExistingAnalysisDetailObjects(context.Context, [][]byte) (map[string]bool, error)
}

const maxDetailNodes = maxItemFPRs + 1
const detailNodeDomain = "insights/detail-node/v1"

// A chain starts with one tools node, followed by request-order pairs. Pair
// nodes remain meaningful past the display cap: they contain only the FPR.
// A prefix reused by another audit reuses every ancestor, not a list of refs.
type detailNode struct {
	Parent string    `json:"parent,omitempty"`
	Kind   string    `json:"kind"`
	Tools  []ToolDef `json:"tools,omitempty"`
	Item   *Item     `json:"item,omitempty"`
	FPR    *string   `json:"fpr,omitempty"`
}
type compactDetailEnvelope struct {
	Schema   int    `json:"detail_schema"`
	Root     string `json:"root"`
	Nodes    int    `json:"nodes"`
	Items    int    `json:"items_count"`
	FPRs     int    `json:"fprs_count"`
	ItemsNil bool   `json:"items_nil,omitempty"`
	FPRsNil  bool   `json:"fprs_nil,omitempty"`
	ToolsNil bool   `json:"tools_nil,omitempty"`
	Detail   Detail `json:"detail"`
}

func detailNodeAAD(hash []byte) ([]byte, error) {
	return security.AAD("insights", "detail_node_v1", hex.EncodeToString(hash))
}

// SealDetailRow builds compact objects only when the target supports atomic
// graph persistence. Legacy stores receive the standalone versioned codec.
func (codec CipherDetailCodec) SealDetailRow(ctx context.Context, auditID string, detail Detail) ([]byte, []byte, []storage.AnalysisDetailObject, error) {
	if ctx == nil || codec.Cipher == nil {
		return nil, nil, nil, errors.New("insights: detail needs context and cipher")
	}
	if codec.Store == nil || codec.Fingerprinter == nil {
		sealed, err := codec.SealDetail(auditID, detail)
		return sealed, nil, nil, err
	}
	if len(detail.Items) > maxDetailItems || len(detail.ItemFPRs) > maxItemFPRs {
		return nil, nil, nil, errors.New("insights: compact detail exceeds item limit")
	}
	count := max(len(detail.Items), len(detail.ItemFPRs))
	nodes := make([]storage.AnalysisDetailObject, 0, count+1)
	plains := make([][]byte, 0, count+1)
	defer func() {
		for _, p := range plains {
			clear(p)
		}
	}()
	var parent []byte
	add := func(node detailNode) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		node.Parent = hex.EncodeToString(parent)
		plain, err := json.Marshal(node)
		if err != nil {
			return err
		}
		plains = append(plains, plain)
		hash := codec.Fingerprinter.Fingerprint(detailNodeDomain, plain)
		if len(hash) != storage.AnalysisFingerprintSize {
			return errors.New("insights: invalid detail fingerprint")
		}
		nodes = append(nodes, storage.AnalysisDetailObject{Hash: hash, ParentHash: parent})
		parent = hash
		return nil
	}
	if err := add(detailNode{Kind: "tools", Tools: detail.Tools}); err != nil {
		return nil, nil, nil, err
	}
	for i := 0; i < count; i++ {
		node := detailNode{Kind: "item"}
		if i < len(detail.Items) {
			item := detail.Items[i]
			node.Item = &item
		}
		if i < len(detail.ItemFPRs) {
			fpr := detail.ItemFPRs[i]
			node.FPR = &fpr
		}
		if err := add(node); err != nil {
			return nil, nil, nil, err
		}
	}
	hashes := make([][]byte, len(nodes))
	for i := range nodes {
		hashes[i] = nodes[i].Hash
	}
	existing, err := codec.Store.ExistingAnalysisDetailObjects(ctx, hashes)
	if err != nil {
		return nil, nil, nil, err
	}
	missing := make([]storage.AnalysisDetailObject, 0, len(nodes))
	for i, node := range nodes {
		if existing[string(node.Hash)] {
			continue
		}
		aad, err := detailNodeAAD(node.Hash)
		if err != nil {
			return nil, nil, nil, err
		}
		encoded, err := encodeDetailPayload(plains[i])
		if err != nil {
			return nil, nil, nil, err
		}
		node.PayloadEnc, err = codec.Cipher.Encrypt(aad, encoded)
		clear(encoded)
		if err != nil {
			return nil, nil, nil, err
		}
		missing = append(missing, node)
	}
	envelope := compactDetailEnvelope{Schema: 2, Root: hex.EncodeToString(parent), Nodes: len(nodes), Items: len(detail.Items), FPRs: len(detail.ItemFPRs), ItemsNil: detail.Items == nil, FPRsNil: detail.ItemFPRs == nil, ToolsNil: detail.Tools == nil, Detail: detail}
	envelope.Detail.Items = nil
	envelope.Detail.ItemFPRs = nil
	envelope.Detail.Tools = nil
	plain, err := json.Marshal(envelope)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(plain)
	encoded, err := encodeDetailPayload(plain)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(encoded)
	aad, err := detailAAD(auditID, AnalysisVersion)
	if err != nil {
		return nil, nil, nil, err
	}
	sealed, err := codec.Cipher.Encrypt(aad, encoded)
	return sealed, parent, missing, err
}

func (codec CipherDetailCodec) openCompact(ctx context.Context, encoded []byte) (Detail, error) {
	var envelope compactDetailEnvelope
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return Detail{}, err
	}
	if envelope.Schema != 2 || codec.Store == nil || envelope.Nodes < 1 || envelope.Nodes > maxDetailNodes || envelope.Items < 0 || envelope.Items > maxDetailItems || envelope.FPRs < 0 || envelope.FPRs > maxItemFPRs || envelope.Nodes != max(envelope.Items, envelope.FPRs)+1 {
		return Detail{}, errors.New("insights: invalid compact detail")
	}
	root, err := hex.DecodeString(envelope.Root)
	if err != nil || len(root) != storage.AnalysisFingerprintSize {
		return Detail{}, errors.New("insights: invalid detail root")
	}
	nodes, err := codec.Store.LoadAnalysisDetailChain(ctx, root, envelope.Nodes)
	if err != nil {
		return Detail{}, err
	}
	if len(nodes) != envelope.Nodes {
		return Detail{}, errors.New("insights: incomplete detail chain")
	}
	detail := envelope.Detail
	if len(detail.Items) != 0 || len(detail.ItemFPRs) != 0 || len(detail.Tools) != 0 {
		return Detail{}, errors.New("insights: unexpected embedded detail")
	}
	detail.Items = make([]Item, envelope.Items)
	detail.ItemFPRs = make([]string, envelope.FPRs)
	expected := root
	seen := make(map[string]bool, len(nodes))
	for i, node := range nodes {
		if err := ctx.Err(); err != nil {
			return Detail{}, err
		}
		if !bytes.Equal(node.Hash, expected) || seen[string(node.Hash)] {
			return Detail{}, errors.New("insights: invalid detail chain")
		}
		seen[string(node.Hash)] = true
		aad, err := detailNodeAAD(node.Hash)
		if err != nil {
			return Detail{}, err
		}
		plain, err := codec.Cipher.Decrypt(aad, node.PayloadEnc)
		if err != nil {
			return Detail{}, err
		}
		decoded, err := decodeDetailPayload(plain)
		clear(plain)
		if err != nil {
			return Detail{}, err
		}
		if codec.Fingerprinter != nil && !bytes.Equal(codec.Fingerprinter.Fingerprint(detailNodeDomain, decoded), node.Hash) {
			clear(decoded)
			return Detail{}, errors.New("insights: detail identity mismatch")
		}
		var payload detailNode
		err = json.Unmarshal(decoded, &payload)
		clear(decoded)
		if err != nil {
			return Detail{}, err
		}
		if payload.Parent != hex.EncodeToString(node.ParentHash) {
			return Detail{}, errors.New("insights: detail parent mismatch")
		}
		index := len(nodes) - i - 2
		if index < 0 {
			if payload.Kind != "tools" || len(node.ParentHash) != 0 || payload.Item != nil || payload.FPR != nil {
				return Detail{}, errors.New("insights: invalid tools node")
			}
			detail.Tools = payload.Tools
		} else {
			if payload.Kind != "item" || len(payload.Tools) != 0 || (payload.Item != nil) != (index < envelope.Items) || (payload.FPR != nil) != (index < envelope.FPRs) {
				return Detail{}, errors.New("insights: invalid item node")
			}
			if payload.Item != nil {
				detail.Items[index] = *payload.Item
			}
			if payload.FPR != nil {
				detail.ItemFPRs[index] = *payload.FPR
			}
		}
		expected = node.ParentHash
	}
	if len(expected) != 0 {
		return Detail{}, fmt.Errorf("insights: unterminated detail chain")
	}
	if envelope.ItemsNil {
		if envelope.Items != 0 {
			return Detail{}, errors.New("insights: invalid nil items")
		}
		detail.Items = nil
	}
	if envelope.FPRsNil {
		if envelope.FPRs != 0 {
			return Detail{}, errors.New("insights: invalid nil fingerprints")
		}
		detail.ItemFPRs = nil
	}
	if envelope.ToolsNil {
		if len(detail.Tools) != 0 {
			return Detail{}, errors.New("insights: invalid nil tools")
		}
		detail.Tools = nil
	} else if detail.Tools == nil {
		detail.Tools = []ToolDef{}
	}
	return detail, nil
}
