package securityaudit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedactOutboundGuardTextReplacesSupportedSensitiveValues(t *testing.T) {
	// 组装无有效签名的测试样本，避免源码秘密扫描将脱敏夹具识别为凭据。
	testJWT := strings.Join([]string{"eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "signature123456"}, ".")
	input := strings.Join([]string{
		"Bearer bearer-secret-123456",
		"sk-secretvalue123",
		testJWT,
		"alice@example.com",
		"+86 138 0013 8000",
		"11010519491231002X",
		"4111 1111 1111 1111",
		"192.0.2.1",
		"[2001:db8::1]",
	}, " ")

	redacted, hasPII := redactOutboundGuardText(input)
	require.True(t, hasPII)
	for _, sensitive := range []string{
		"bearer-secret-123456", "secretvalue123", "eyJhbGciOiJIUzI1NiJ9",
		"alice@example.com", "138 0013 8000", "11010519491231002X",
		"4111 1111 1111 1111", "192.0.2.1", "2001:db8::1",
	} {
		require.NotContains(t, redacted, sensitive)
	}
	require.GreaterOrEqual(t, strings.Count(redacted, "<CREDENTIAL>"), 3)
	require.Contains(t, redacted, "<EMAIL>")
	require.Contains(t, redacted, "<PHONE>")
	require.Contains(t, redacted, "<CN_ID>")
	require.Contains(t, redacted, "<BANK_CARD>")
	require.Equal(t, 2, strings.Count(redacted, "<IP_ADDRESS>"))
}

func TestRedactOutboundGuardTextValidatesNumericCandidates(t *testing.T) {
	input := "invalid id 11010520230230002X invalid card 4111111111111112 invalid ip 999.999.999.999"
	redacted, hasPII := redactOutboundGuardText(input)
	require.Equal(t, input, redacted)
	require.False(t, hasPII)
}

func TestRedactOutboundGuardTextNoMatchAndCredentialOnly(t *testing.T) {
	plain := "ordinary review text without direct identifiers"
	redacted, hasPII := redactOutboundGuardText(plain)
	require.Equal(t, plain, redacted)
	require.False(t, hasPII)

	credential := "password=supersecret123"
	redacted, hasPII = redactOutboundGuardText(credential)
	require.Equal(t, "<CREDENTIAL>", redacted)
	require.False(t, hasPII)
}

func TestOpenAICompatibleScannerSendsOnlyRedactedSensitiveValues(t *testing.T) {
	const email = "alice@example.com"
	const token = "sk-secretvalue123"
	var received string
	server := newGuardResponseServer(t, func(content string) string {
		received = content
		return "Safety: Safe\nCategories: none"
	})
	defer server.Close()

	result, err := NewOpenAICompatibleScanner().Scan(context.Background(), ActiveEndpoint{
		ID: "guard", BaseURL: server.URL, Model: DefaultGuardModel, TimeoutMS: 1000,
	}, "contact "+email+" using "+token, AllScannerIDs)
	require.NoError(t, err)
	require.Equal(t, EventPass, result.Decision)
	require.NotContains(t, received, email)
	require.NotContains(t, received, token)
	require.Contains(t, received, "<EMAIL>")
	require.Contains(t, received, "<CREDENTIAL>")
}

func TestOpenAICompatibleScannerMergesLocalPIISignalByPolicy(t *testing.T) {
	tests := []struct {
		name       string
		guard      string
		scanners   []string
		content    string
		want       EventDecision
		wantAction Action
		wantPII    bool
	}{
		{name: "safe stays safe", guard: "Safety: Safe\nCategories: none", scanners: []string{"pii"}, content: "alice@example.com", want: EventPass, wantAction: ActionAllow},
		{name: "enabled pii elevates controversial", guard: "Safety: Controversial\nCategories: none", scanners: []string{"pii"}, content: "alice@example.com", want: EventCritical, wantAction: ActionBlock, wantPII: true},
		{name: "disabled pii cannot affect decision", guard: "Safety: Controversial\nCategories: none", scanners: []string{"jailbreak"}, content: "alice@example.com", want: EventPass, wantAction: ActionAllow},
		{name: "credential is not pii", guard: "Safety: Controversial\nCategories: none", scanners: []string{"pii"}, content: "password=supersecret123", want: EventPass, wantAction: ActionAllow},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			server := newGuardResponseServer(t, func(string) string { return testCase.guard })
			defer server.Close()
			result, err := NewOpenAICompatibleScanner().Scan(context.Background(), ActiveEndpoint{
				ID: "guard", BaseURL: server.URL, Model: DefaultGuardModel, TimeoutMS: 1000,
			}, testCase.content, testCase.scanners)
			require.NoError(t, err)
			require.Equal(t, testCase.want, result.Decision)
			require.Equal(t, testCase.wantAction, result.Action)
			require.Equal(t, testCase.wantPII, containsScanner(result.MatchedScanners, "pii"))
			if testCase.wantPII {
				require.Equal(t, 0.5, result.ScannerScores["pii"])
				require.Equal(t, ScannerCatalog["pii"].Label, result.ScannerEvidence["pii"])
			}
		})
	}
}

func TestGuardFailoverAlwaysUsesRedactedOutboundContent(t *testing.T) {
	const email = "failover@example.com"
	var mu sync.Mutex
	received := make([]string, 0, 4)
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content := decodeGuardRequestContent(t, r)
		mu.Lock()
		received = append(received, content)
		mu.Unlock()
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer first.Close()
	second := newGuardResponseServer(t, func(content string) string {
		mu.Lock()
		received = append(received, content)
		mu.Unlock()
		return "Safety: Safe\nCategories: none"
	})
	defer second.Close()
	endpoints := []ActiveEndpoint{
		{ID: "first", BaseURL: first.URL, Model: DefaultGuardModel, Enabled: true, TimeoutMS: 1000, InputLimit: 4096},
		{ID: "second", BaseURL: second.URL, Model: DefaultGuardModel, Enabled: true, TimeoutMS: 1000, InputLimit: 4096},
	}
	scanner := NewOpenAICompatibleScanner()

	_, err := newGuardEvaluator(scanner, nil, NewAtomicMetrics(), 1, 1).Evaluate(context.Background(), ActiveConfig{
		Scanners: []string{"pii"}, Endpoints: endpoints,
	}, PromptSnapshot{ScanText: email, PromptLength: len(email)})
	require.NoError(t, err)
	_, err = scanWithFailover(context.Background(), scanner, []string{"pii"}, endpoints, email, NewAtomicMetrics())
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, received, 4)
	for _, content := range received {
		require.NotContains(t, content, email)
		require.Contains(t, content, "<EMAIL>")
	}
}

func newGuardResponseServer(t *testing.T, response func(string) string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content := decodeGuardRequestContent(t, r)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"content": response(content)}}},
		})
	}))
}

func decodeGuardRequestContent(t *testing.T, request *http.Request) string {
	t.Helper()
	var payload struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	require.NoError(t, json.NewDecoder(request.Body).Decode(&payload))
	require.Len(t, payload.Messages, 1)
	return payload.Messages[0].Content
}

func containsScanner(scanners []string, expected string) bool {
	for _, scanner := range scanners {
		if scanner == expected {
			return true
		}
	}
	return false
}

var outboundRedactionBenchmarkSink string

func BenchmarkRedactOutboundGuardText(b *testing.B) {
	plain := strings.Repeat("ordinary review content without identifiers ", 5000)
	matched := plain[:len(plain)/2] + " alice@example.com " + plain[len(plain)/2:]
	for _, benchmark := range []struct {
		name  string
		value string
	}{
		{name: "no_match_200k", value: plain},
		{name: "one_match_200k", value: matched},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			for index := 0; index < b.N; index++ {
				outboundRedactionBenchmarkSink, _ = redactOutboundGuardText(benchmark.value)
			}
		})
	}
}
