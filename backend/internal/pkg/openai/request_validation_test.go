package openai

import "testing"

// 校验首尾、内部和折行控制字符，不能因去空白而恢复成貌似有效的身份。
func TestCodexRawUserAgentValidation(t *testing.T) {
	valid := "codex-tui/0.200.1 (Linux; x86_64) terminal"
	for _, raw := range []string{"\r" + valid, valid + "\n", valid + "\r\n X-Fake: test", valid + "\x00", valid + "\x7f", valid + "\v"} {
		if _, _, ok := PairCodexClientIdentity(raw); ok {
			t.Errorf("非法原始 UA 被配对: %q", raw)
		}
		if _, ok := ParseCodexEngineVersion(raw); ok {
			t.Errorf("非法原始 UA 被用于版本解析: %q", raw)
		}
	}
	if origin, paired, ok := PairCodexClientIdentity(" \t" + valid + "\t "); !ok || origin != "codex-tui" || paired != valid {
		t.Fatalf("合法平台和终端后缀未保留: %q %q %v", origin, paired, ok)
	}
}
