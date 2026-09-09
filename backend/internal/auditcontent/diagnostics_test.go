package auditcontent

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDescribeExtractionFailuresReportsStructureWithoutValues(t *testing.T) {
	const canary = "EXTRACTION_DIAGNOSTIC_CANARY_DO_NOT_LOG"
	body := []byte(`{"input":[{"type":"future_response_item","payload":"` + canary + `","nested":{"message":"` + canary + `"}}]}`)
	details := DescribeExtractionFailures(body, []IncompleteReason{{
		Kind: IncompleteUnsupportedItemType, Path: "input.[0]", ItemType: "unknown_item_type",
	}})

	require.Len(t, details, 1)
	detail := details[0]
	require.Equal(t, "future_response_item", detail.ItemType)
	require.Equal(t, "object", detail.NodeKind)
	require.Equal(t, []string{"nested", "payload", "type"}, detail.NodeKeys)
	require.Contains(t, detail.NodeShape, `"type":"future_response_item"`)
	require.Contains(t, detail.NodeShape, `"payload":"$string"`)
	require.Contains(t, detail.NodeShape, `"nested":{"message":"$string"}`)
	require.NotContains(t, detail.NodeShape, canary)
	require.Len(t, detail.ItemTypeFingerprint, 64)
	require.Len(t, detail.ShapeFingerprint, 64)
	require.Positive(t, detail.NodeBytes)

	raw, err := json.Marshal(details)
	require.NoError(t, err)
	require.NotContains(t, string(raw), canary)
}

func TestDescribeExtractionFailuresRedactsCredentialLikeIdentifiers(t *testing.T) {
	const credentialLikeType = "secret_token_1234567890abcdef"
	details := DescribeExtractionFailures(
		[]byte(`{"input":[{"type":"`+credentialLikeType+`","api_key_value":"hidden"}]}`),
		[]IncompleteReason{{Kind: IncompleteUnsupportedItemType, Path: "input.[0]"}},
	)

	require.Len(t, details, 1)
	require.Equal(t, "unknown_item_type", details[0].ItemType)
	require.NotContains(t, details[0].NodeShape, credentialLikeType)
	require.NotContains(t, details[0].NodeKeys, "api_key_value")
	require.Len(t, details[0].ItemTypeFingerprint, 64)
}

func TestDescribeExtractionFailuresReportsInvalidJSONOffset(t *testing.T) {
	details := DescribeExtractionFailures([]byte(`{"input":`), nil)

	require.Equal(t, []ExtractionFailureDetail{{
		Kind: IncompleteUnextractable, Path: "$", NodeKind: "invalid_json", JSONErrorOffset: 10,
	}}, details)
}

func TestSanitizeExtractionFailureDetailsRebuildsUntrustedShape(t *testing.T) {
	const canary = "UNTRUSTED_SHAPE_CANARY_DO_NOT_LOG"
	details := SanitizeExtractionFailureDetails([]ExtractionFailureDetail{{
		Kind: IncompleteUnextractable, NodeKind: "object",
		NodeShape: `{"payload":"` + canary + `","type":"future_response_item"}`,
	}})

	require.Len(t, details, 1)
	require.JSONEq(t, `{"payload":"$string","type":"future_response_item"}`, details[0].NodeShape)
	require.NotContains(t, details[0].NodeShape, canary)
	require.Len(t, details[0].ShapeFingerprint, 64)
}
