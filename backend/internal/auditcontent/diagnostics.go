package auditcontent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

const (
	maxFailureDetails    = maxIncompleteReasons
	maxFailureNodeKeys   = 16
	maxFailureShapeDepth = 4
	maxFailureShapeNodes = 96
	maxFailureShapeBytes = 4096
)

// ExtractionFailureDetail describes only the structure of a failed node. It
// never contains message text, tool payload values, credentials, or media.
type ExtractionFailureDetail struct {
	Kind                IncompleteKind `json:"kind"`
	Path                string         `json:"path,omitempty"`
	Field               string         `json:"field,omitempty"`
	ItemType            string         `json:"item_type,omitempty"`
	ItemTypeFingerprint string         `json:"item_type_fingerprint,omitempty"`
	NodeKind            string         `json:"node_kind"`
	NodeKeys            []string       `json:"node_keys,omitempty"`
	NodeShape           string         `json:"node_shape,omitempty"`
	NodeBytes           int            `json:"node_bytes,omitempty"`
	ShapeFingerprint    string         `json:"shape_fingerprint,omitempty"`
	JSONErrorOffset     int64          `json:"json_error_offset,omitempty"`
}

// DescribeExtractionFailures resolves each canonical failure path and emits a
// bounded, value-free structural description suitable for production logs.
func DescribeExtractionFailures(body []byte, reasons []IncompleteReason) []ExtractionFailureDetail {
	root, err := decodeDiagnosticJSON(body)
	if err != nil {
		detail := ExtractionFailureDetail{Kind: IncompleteUnextractable, Path: "$", NodeKind: "invalid_json"}
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			detail.JSONErrorOffset = syntaxErr.Offset
		} else if errors.Is(err, io.ErrUnexpectedEOF) {
			detail.JSONErrorOffset = int64(len(body) + 1)
		}
		return []ExtractionFailureDetail{detail}
	}
	if len(reasons) == 0 {
		return nil
	}
	if len(reasons) > maxFailureDetails {
		reasons = reasons[:maxFailureDetails]
	}
	details := make([]ExtractionFailureDetail, 0, len(reasons))
	for _, reason := range reasons {
		reason = sanitizeIncompleteReason(reason)
		node, ok := resolveDiagnosticPath(root, reason.Path)
		if !ok {
			details = append(details, ExtractionFailureDetail{
				Kind: reason.Kind, Path: reason.Path, Field: reason.Field, NodeKind: "unresolved",
			})
			continue
		}
		detail := describeFailureNode(reason, node)
		details = append(details, detail)
	}
	return SanitizeExtractionFailureDetails(details)
}

func SanitizeExtractionFailureDetails(details []ExtractionFailureDetail) []ExtractionFailureDetail {
	if len(details) == 0 {
		return nil
	}
	if len(details) > maxFailureDetails {
		details = details[:maxFailureDetails]
	}
	out := make([]ExtractionFailureDetail, 0, len(details))
	for _, detail := range details {
		reason := sanitizeIncompleteReason(IncompleteReason{
			Kind: detail.Kind, Path: detail.Path, Field: detail.Field,
		})
		detail.Kind, detail.Path, detail.Field = reason.Kind, reason.Path, reason.Field
		detail.ItemType = safeDiagnosticIdentifier(detail.ItemType, "unknown_item_type")
		detail.ItemTypeFingerprint = safeFingerprint(detail.ItemTypeFingerprint)
		detail.NodeKind = safeDiagnosticIdentifier(detail.NodeKind, "unknown")
		if len(detail.NodeKeys) > maxFailureNodeKeys {
			detail.NodeKeys = detail.NodeKeys[:maxFailureNodeKeys]
		}
		for i, key := range detail.NodeKeys {
			detail.NodeKeys[i] = safeDiagnosticKey(key)
		}
		if detail.NodeShape != "" {
			detail.NodeShape = sanitizeDiagnosticShape(detail.NodeShape)
			if detail.NodeShape != "" {
				detail.ShapeFingerprint = fingerprint(detail.NodeShape)
			}
		}
		detail.ShapeFingerprint = safeFingerprint(detail.ShapeFingerprint)
		if detail.NodeBytes < 0 {
			detail.NodeBytes = 0
		}
		if detail.JSONErrorOffset < 0 {
			detail.JSONErrorOffset = 0
		}
		out = append(out, detail)
	}
	return out
}

func sanitizeDiagnosticShape(encoded string) string {
	value, err := decodeDiagnosticJSON([]byte(encoded))
	if err != nil {
		return ""
	}
	budget := maxFailureShapeNodes
	shape := diagnosticShape(value, 0, &budget, "")
	raw, err := json.Marshal(shape)
	if err != nil {
		return ""
	}
	if len(raw) > maxFailureShapeBytes {
		return `{"truncated":"$boolean"}`
	}
	return string(raw)
}

func decodeDiagnosticJSON(body []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("multiple JSON values")
		}
		return nil, err
	}
	return decoded, nil
}

func describeFailureNode(reason IncompleteReason, node any) ExtractionFailureDetail {
	detail := ExtractionFailureDetail{
		Kind: reason.Kind, Path: reason.Path, Field: reason.Field, NodeKind: diagnosticValueKind(node),
	}
	if raw, err := json.Marshal(node); err == nil {
		detail.NodeBytes = len(raw)
	}
	if object, ok := node.(map[string]any); ok {
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, safeDiagnosticKey(key))
		}
		sort.Strings(keys)
		if len(keys) > maxFailureNodeKeys {
			keys = keys[:maxFailureNodeKeys]
		}
		detail.NodeKeys = keys
		if rawType, ok := object["type"].(string); ok && strings.TrimSpace(rawType) != "" {
			normalized := strings.ToLower(strings.TrimSpace(rawType))
			detail.ItemType = safeDiagnosticIdentifier(normalized, "unknown_item_type")
			detail.ItemTypeFingerprint = fingerprint(normalized)
		}
	}
	if detail.ItemType == "" && reason.ItemType != "" && reason.ItemType != "unknown_item_type" {
		detail.ItemType = safeDiagnosticIdentifier(reason.ItemType, "unknown_item_type")
		detail.ItemTypeFingerprint = fingerprint(reason.ItemType)
	}
	budget := maxFailureShapeNodes
	shape := diagnosticShape(node, 0, &budget, "")
	if raw, err := json.Marshal(shape); err == nil {
		detail.ShapeFingerprint = fingerprint(string(raw))
		if len(raw) <= maxFailureShapeBytes {
			detail.NodeShape = string(raw)
		} else {
			detail.NodeShape = `"<shape_truncated>"`
		}
	}
	return detail
}

func diagnosticShape(value any, depth int, budget *int, semanticKey string) any {
	if *budget <= 0 || depth >= maxFailureShapeDepth {
		return "$truncated"
	}
	*budget--
	switch typed := value.(type) {
	case nil:
		return "$null"
	case bool:
		return "$boolean"
	case json.Number, float64:
		return "$number"
	case string:
		if semanticKey == "type" || semanticKey == "role" {
			return safeDiagnosticIdentifier(strings.ToLower(strings.TrimSpace(typed)), "redacted_identifier")
		}
		switch typed {
		case "$string", "$number", "$boolean", "$null", "$unknown", "$truncated":
			return typed
		}
		return "$string"
	case []any:
		shapes := make([]any, 0, 4)
		seen := make(map[string]struct{}, 4)
		for _, item := range typed {
			shape := diagnosticShape(item, depth+1, budget, "")
			raw, _ := json.Marshal(shape)
			key := string(raw)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			shapes = append(shapes, shape)
			if len(shapes) == 4 || *budget <= 0 {
				break
			}
		}
		return shapes
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if len(keys) > maxFailureNodeKeys {
			keys = keys[:maxFailureNodeKeys]
		}
		shape := make(map[string]any, len(keys))
		for _, key := range keys {
			shape[safeDiagnosticKey(key)] = diagnosticShape(typed[key], depth+1, budget, strings.ToLower(strings.TrimSpace(key)))
			if *budget <= 0 {
				break
			}
		}
		return shape
	default:
		return "$" + diagnosticValueKind(value)
	}
}

func resolveDiagnosticPath(root any, path string) (any, bool) {
	if strings.TrimSpace(path) == "" || path == "$" {
		return root, true
	}
	current := root
	for index := 0; index < len(path); {
		switch path[index] {
		case '.':
			index++
		case '[':
			end := strings.IndexByte(path[index:], ']')
			if end <= 1 {
				return nil, false
			}
			arrayIndex, err := strconv.Atoi(path[index+1 : index+end])
			values, ok := current.([]any)
			if err != nil || !ok || arrayIndex < 0 || arrayIndex >= len(values) {
				return nil, false
			}
			current = values[arrayIndex]
			index += end + 1
		default:
			end := index
			for end < len(path) && path[end] != '.' && path[end] != '[' {
				end++
			}
			object, ok := current.(map[string]any)
			if !ok {
				return nil, false
			}
			current, ok = object[path[index:end]]
			if !ok {
				return nil, false
			}
			index = end
		}
	}
	return current, true
}

func diagnosticValueKind(value any) string {
	switch value.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case json.Number, float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "unknown"
	}
}

func safeDiagnosticIdentifier(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if len(value) > 48 || looksSensitiveDiagnosticIdentifier(value) {
		return fallback
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '_' || char == '-' || char == '.' {
			continue
		}
		return fallback
	}
	return value
}

func safeDiagnosticKey(value string) string {
	safe := safeDiagnosticIdentifier(value, "")
	if safe != "" && len(safe) <= 48 {
		return safe
	}
	return fmt.Sprintf("key_%s", fingerprint(value)[:12])
}

func looksSensitiveDiagnosticIdentifier(value string) bool {
	for _, marker := range []string{"api_key", "apikey", "bearer", "password", "secret", "token"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	if len(value) < 24 {
		return false
	}
	compact := strings.NewReplacer("_", "", "-", "", ".", "").Replace(value)
	if len(compact) < 24 {
		return false
	}
	for _, char := range compact {
		if char >= '0' && char <= '9' || char >= 'a' && char <= 'f' {
			continue
		}
		return false
	}
	return true
}

func fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func safeFingerprint(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != sha256.Size*2 {
		return ""
	}
	if _, err := hex.DecodeString(value); err != nil {
		return ""
	}
	return value
}
