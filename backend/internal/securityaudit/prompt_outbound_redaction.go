package securityaudit

import (
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	outboundJWT                   = regexp.MustCompile(`\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)
	outboundStandaloneCredential  = regexp.MustCompile(`(?i)\b(?:sk|rk|pk)-[A-Za-z0-9_-]{8,}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bAIza[0-9A-Za-z_-]{35}\b|\bGOCSPX-[0-9A-Za-z_-]{24,}\b|\bAKIA[0-9A-Z]{16}\b`)
	outboundCNIDCandidate         = regexp.MustCompile(`(?i)\b[1-9][0-9]{16}[0-9X]\b`)
	outboundBankCardCandidate     = regexp.MustCompile(`\b(?:[0-9]{13,19}|[0-9]{4}(?:[ -][0-9]{4}){3})\b`)
	outboundChinesePhoneCandidate = regexp.MustCompile(`(?:\+?86[ -]?)?1[3-9][0-9](?:[ -]?[0-9]){8}\b`)
	outboundIntlPhoneCandidate    = regexp.MustCompile(`\+[1-9][0-9]{7,14}\b`)
	outboundLocalPhoneCandidate   = regexp.MustCompile(`\b[0-9]{2,4}[ -][0-9]{3,4}[ -][0-9]{4}\b`)
)

type outboundRedactionSpan struct {
	start       int
	end         int
	placeholder string
	priority    int
	pii         bool
}

func redactOutboundGuardText(value string) (string, bool) {
	if value == "" {
		return value, false
	}

	var spans []outboundRedactionSpan
	appendPatternSpans := func(pattern *regexp.Regexp, placeholder string, priority int, pii bool) {
		for _, match := range pattern.FindAllStringIndex(value, -1) {
			spans = append(spans, outboundRedactionSpan{
				start: match[0], end: match[1],
				placeholder: placeholder, priority: priority, pii: pii,
			})
		}
	}

	if containsASCIIFold(value, "bearer ") {
		appendPatternSpans(bearerPattern, "<CREDENTIAL>", 100, false)
	}
	if containsCredentialAssignmentHint(value) {
		appendPatternSpans(apiKeyPattern, "<CREDENTIAL>", 100, false)
	}
	if containsASCIIFold(value, "_canary_") {
		appendPatternSpans(canaryPattern, "<CREDENTIAL>", 100, false)
	}
	if strings.Count(value, ".") >= 2 {
		appendPatternSpans(outboundJWT, "<CREDENTIAL>", 100, false)
	}
	if strings.ContainsAny(value, "-_") || strings.Contains(value, "AIza") || strings.Contains(value, "AKIA") {
		appendPatternSpans(outboundStandaloneCredential, "<CREDENTIAL>", 100, false)
	}
	if strings.IndexByte(value, '@') >= 0 {
		appendPatternSpans(emailPattern, "<EMAIL>", 90, true)
	}

	if containsASCIIDigit(value) {
		for _, match := range outboundCNIDCandidate.FindAllStringIndex(value, -1) {
			if validChineseIdentityNumber(value[match[0]:match[1]]) {
				spans = append(spans, outboundRedactionSpan{
					start: match[0], end: match[1],
					placeholder: "<CN_ID>", priority: 80, pii: true,
				})
			}
		}
		for _, match := range outboundBankCardCandidate.FindAllStringIndex(value, -1) {
			if validBankCardNumber(value[match[0]:match[1]]) {
				spans = append(spans, outboundRedactionSpan{
					start: match[0], end: match[1],
					placeholder: "<BANK_CARD>", priority: 70, pii: true,
				})
			}
		}
		for _, pattern := range []*regexp.Regexp{outboundChinesePhoneCandidate, outboundIntlPhoneCandidate, outboundLocalPhoneCandidate} {
			for _, match := range pattern.FindAllStringIndex(value, -1) {
				if validTelephoneCandidate(value[match[0]:match[1]]) {
					spans = append(spans, outboundRedactionSpan{
						start: match[0], end: match[1],
						placeholder: "<PHONE>", priority: 60, pii: true,
					})
				}
			}
		}
		if strings.IndexByte(value, '.') >= 0 || strings.IndexByte(value, ':') >= 0 {
			for _, match := range outboundIPAddressSpans(value) {
				spans = append(spans, outboundRedactionSpan{
					start: match[0], end: match[1],
					placeholder: "<IP_ADDRESS>", priority: 50, pii: true,
				})
			}
		}
	}

	if len(spans) == 0 {
		return value, false
	}
	selected := selectOutboundRedactionSpans(spans, len(value))
	if len(selected) == 0 {
		return value, false
	}

	var builder strings.Builder
	builder.Grow(len(value))
	last := 0
	hasPII := false
	for _, span := range selected {
		_, _ = builder.WriteString(value[last:span.start])
		_, _ = builder.WriteString(span.placeholder)
		last = span.end
		hasPII = hasPII || span.pii
	}
	_, _ = builder.WriteString(value[last:])
	return builder.String(), hasPII
}

func selectOutboundRedactionSpans(spans []outboundRedactionSpan, valueLength int) []outboundRedactionSpan {
	sort.SliceStable(spans, func(i, j int) bool {
		if spans[i].priority != spans[j].priority {
			return spans[i].priority > spans[j].priority
		}
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end > spans[j].end
	})
	selected := make([]outboundRedactionSpan, 0, len(spans))
	for _, span := range spans {
		if span.start < 0 || span.end <= span.start || span.end > valueLength {
			continue
		}
		insertAt := sort.Search(len(selected), func(index int) bool {
			return selected[index].end > span.start
		})
		if insertAt < len(selected) && selected[insertAt].start < span.end {
			continue
		}
		selected = append(selected, outboundRedactionSpan{})
		copy(selected[insertAt+1:], selected[insertAt:])
		selected[insertAt] = span
	}
	return selected
}

func validChineseIdentityNumber(value string) bool {
	if len(value) != 18 {
		return false
	}
	if _, err := time.Parse("20060102", value[6:14]); err != nil {
		return false
	}
	weights := [...]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	checks := "10X98765432"
	sum := 0
	for index := 0; index < 17; index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
		sum += int(value[index]-'0') * weights[index]
	}
	actual := value[17]
	if actual == 'x' {
		actual = 'X'
	}
	return actual == checks[sum%11]
}

func validBankCardNumber(value string) bool {
	digits := make([]byte, 0, len(value))
	for index := 0; index < len(value); index++ {
		if value[index] >= '0' && value[index] <= '9' {
			digits = append(digits, value[index])
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	double := false
	for index := len(digits) - 1; index >= 0; index-- {
		digit := int(digits[index] - '0')
		if double {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		double = !double
	}
	return sum%10 == 0
}

func validTelephoneCandidate(value string) bool {
	if strings.Count(value, ".") >= 2 {
		return false
	}
	digits := 0
	for index := 0; index < len(value); index++ {
		if value[index] >= '0' && value[index] <= '9' {
			digits++
		}
	}
	return digits >= 10 && digits <= 15
}

func containsCredentialAssignmentHint(value string) bool {
	return containsASCIIFold(value, "token") || containsASCIIFold(value, "secret") ||
		containsASCIIFold(value, "password") || containsASCIIFold(value, "api_key") ||
		containsASCIIFold(value, "api-key") || containsASCIIFold(value, "sk-") ||
		containsASCIIFold(value, "rk-") || containsASCIIFold(value, "pk-")
}

func containsASCIIDigit(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] >= '0' && value[index] <= '9' {
			return true
		}
	}
	return false
}

func containsASCIIFold(value, needle string) bool {
	if needle == "" || len(needle) > len(value) {
		return false
	}
	for start := 0; start <= len(value)-len(needle); start++ {
		matched := true
		for offset := 0; offset < len(needle); offset++ {
			left, right := value[start+offset], needle[offset]
			if left >= 'A' && left <= 'Z' {
				left += 'a' - 'A'
			}
			if right >= 'A' && right <= 'Z' {
				right += 'a' - 'A'
			}
			if left != right {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func outboundIPAddressSpans(value string) [][2]int {
	result := make([][2]int, 0, 2)
	for start := 0; start < len(value); {
		if !isIPCandidateByte(value[start]) {
			start++
			continue
		}
		end := start + 1
		for end < len(value) && isIPCandidateByte(value[end]) {
			end++
		}
		candidateEnd := end
		for candidateEnd > start && value[candidateEnd-1] == '.' {
			candidateEnd--
		}
		candidate := value[start:candidateEnd]
		colonCount := strings.Count(candidate, ":")
		dotCount := strings.Count(candidate, ".")
		if colonCount < 2 && dotCount != 3 {
			start = end
			continue
		}
		if net.ParseIP(candidate) != nil {
			result = append(result, [2]int{start, candidateEnd})
			start = end
			continue
		}
		if dotCount == 3 {
			if colon := strings.LastIndexByte(candidate, ':'); colon > 0 && net.ParseIP(candidate[:colon]) != nil {
				result = append(result, [2]int{start, start + colon})
			}
		}
		start = end
	}
	return result
}

func isIPCandidateByte(value byte) bool {
	return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') ||
		(value >= 'A' && value <= 'F') || value == ':' || value == '.'
}

func applyOutboundPIISignal(result *NormalizedResult, hasPII bool, enabledScanners []string) {
	if result == nil || !hasPII || result.Safety == "Safe" || !outboundScannerEnabled(enabledScanners, "pii") {
		return
	}
	matched := make(map[string]struct{}, len(result.MatchedScanners)+1)
	for _, scanner := range result.MatchedScanners {
		matched[scanner] = struct{}{}
	}
	matched["pii"] = struct{}{}
	result.MatchedScanners = orderedScannerKeys(matched)
	result.Categories = append([]string(nil), result.MatchedScanners...)
	if result.ScannerScores == nil {
		result.ScannerScores = map[string]float64{}
	}
	if result.ScannerEvidence == nil {
		result.ScannerEvidence = map[string]string{}
	}
	score := 0.5
	if result.Safety == "Unsafe" {
		score = 1
	}
	if score > result.ScannerScores["pii"] {
		result.ScannerScores["pii"] = score
	}
	result.ScannerEvidence["pii"] = ScannerCatalog["pii"].Label
	result.Decision, result.RiskLevel, result.Action = EventCritical, RiskCritical, ActionBlock
}

func outboundScannerEnabled(enabledScanners []string, scannerID string) bool {
	for _, scanner := range enabledScanners {
		if NormalizeCategory(scanner) == scannerID {
			return true
		}
	}
	return false
}
