package securityaudit

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/TokenFlux/TokenRouter/internal/auditcontent"
)

const completeContextFormatVersion = 1

type completeContextSegment struct {
	Index            int                 `json:"index"`
	Source           auditcontent.Source `json:"source"`
	Role             string              `json:"role,omitempty"`
	Current          bool                `json:"current"`
	ClientControlled bool                `json:"client_controlled"`
	Text             string              `json:"text"`
}

type completeContextImage struct {
	Index            int                 `json:"index"`
	Source           auditcontent.Source `json:"source"`
	Role             string              `json:"role,omitempty"`
	Current          bool                `json:"current"`
	ClientControlled bool                `json:"client_controlled"`
	URL              string              `json:"url"`
}

type completePromptContext struct {
	FormatVersion      int                             `json:"format_version"`
	CapturedAt         time.Time                       `json:"captured_at"`
	RequestID          string                          `json:"request_id"`
	Endpoint           string                          `json:"endpoint"`
	Protocol           string                          `json:"protocol"`
	Model              string                          `json:"model"`
	Stage              string                          `json:"stage"`
	BodyBytes          int                             `json:"body_bytes"`
	ContentBearing     bool                            `json:"content_bearing"`
	ExtractionComplete bool                            `json:"extraction_complete"`
	IncompleteReasons  []auditcontent.IncompleteReason `json:"incomplete_reasons,omitempty"`
	GuardMode          string                          `json:"guard_mode"`
	GuardModules       ReviewModules                   `json:"guard_modules"`
	GuardInput         string                          `json:"guard_input"`
	AllowReceiptStatus string                          `json:"allow_receipt_status,omitempty"`
	AllowReceiptHits   int                             `json:"allow_receipt_hits,omitempty"`
	AllowReceiptMisses int                             `json:"allow_receipt_misses,omitempty"`
	Segments           []completeContextSegment        `json:"segments"`
	Images             []completeContextImage          `json:"images"`
}

type transientPromptPayload struct {
	FormatVersion        int      `json:"format_version"`
	ScanText             string   `json:"scan_text"`
	ContextCiphertext    string   `json:"context_ciphertext,omitempty"`
	ContextHash          string   `json:"context_hash,omitempty"`
	ContextBytes         int      `json:"context_bytes,omitempty"`
	ContextSegmentCount  int      `json:"context_segment_count,omitempty"`
	AllowReceiptKeys     []string `json:"allow_receipt_keys,omitempty"`
	AllowReceiptHitCount int      `json:"allow_receipt_hit_count,omitempty"`
	AllowReceiptWrite    bool     `json:"allow_receipt_write,omitempty"`
}

type EventContextDownload struct {
	JSON   []byte
	SHA256 string
}

func buildCompletePromptContext(req Request, document auditcontent.Document, diagnostic promptExtractionDiagnostic, snapshot PromptSnapshot, selection promptSelection, modules ReviewModules) (string, string, int, int, error) {
	segments := make([]completeContextSegment, 0, len(document.Segments))
	for index, segment := range document.Segments {
		segments = append(segments, completeContextSegment{
			Index: index, Source: segment.Source, Role: segment.Role, Current: segment.Current,
			ClientControlled: segment.ClientControlled, Text: segment.Text,
		})
	}
	images := make([]completeContextImage, 0, len(document.Images))
	for index, image := range document.Images {
		images = append(images, completeContextImage{
			Index: index, Source: image.Source, Role: image.Role, Current: image.Current,
			ClientControlled: image.ClientControlled, URL: image.URL,
		})
	}
	payload := completePromptContext{
		FormatVersion: completeContextFormatVersion, CapturedAt: time.Now().UTC(),
		RequestID: req.RequestID, Endpoint: req.Endpoint, Protocol: req.Protocol, Model: req.Model,
		Stage: normalizeStage(req.Stage), BodyBytes: len(req.Body), ContentBearing: document.ContentBearing,
		ExtractionComplete: !diagnostic.Failed, IncompleteReasons: diagnostic.Reasons,
		GuardMode: string(selection), GuardModules: modules, GuardInput: snapshot.FullPrompt, Segments: segments, Images: images,
	}
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", "", 0, 0, err
	}
	digest := sha256.Sum256(raw)
	return string(raw), hex.EncodeToString(digest[:]), len(raw), len(segments), nil
}

func encryptCompletePromptContext(config ConfigStore, plaintext string) (string, error) {
	if config == nil || plaintext == "" {
		return "", errors.New("prompt audit complete context unavailable")
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(plaintext)); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	return config.Encrypt(base64.StdEncoding.EncodeToString(compressed.Bytes()))
}

func decryptCompletePromptContext(config ConfigStore, ciphertext string) ([]byte, error) {
	if config == nil || strings.TrimSpace(ciphertext) == "" {
		return nil, ErrEventContextNotFound
	}
	encoded, err := config.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}
	compressed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	return io.ReadAll(reader)
}

func encodeTransientPromptPayload(snapshot PromptSnapshot) (string, error) {
	payload := transientPromptPayload{
		FormatVersion: completeContextFormatVersion, ScanText: snapshot.ScanText,
		ContextCiphertext: snapshot.FullContextCiphertext, ContextHash: snapshot.FullContextHash,
		ContextBytes: snapshot.FullContextBytes, ContextSegmentCount: snapshot.FullContextSegmentCount,
		AllowReceiptKeys: append([]string(nil), snapshot.AllowReceiptKeys...), AllowReceiptHitCount: snapshot.AllowReceiptHitCount,
		AllowReceiptWrite: snapshot.AllowReceiptWrite,
	}
	raw, err := json.Marshal(payload)
	return string(raw), err
}

func decodeTransientPromptPayload(value string) transientPromptPayload {
	var payload transientPromptPayload
	if json.Unmarshal([]byte(value), &payload) == nil && payload.FormatVersion == completeContextFormatVersion && payload.ScanText != "" {
		return payload
	}
	return transientPromptPayload{ScanText: value}
}
