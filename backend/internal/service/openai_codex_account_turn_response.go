package service

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// codexTurnResponseObserver 旁观实际已读取的响应，不提前消费流或改变客户端事件。
// 仅识别完整成功终态；超限、错误、取消或不完整响应都不能触发状态轮换。
type codexTurnResponseObserver struct {
	io.ReadCloser
	sse       bool
	pending   []byte
	succeeded bool
	failed    bool
	writer    *codexTurnClientWriter
}

// 下游写失败时即使继续 drain 到成功终态，也不能更新账号状态。
type codexTurnClientWriter struct {
	gin.ResponseWriter
	failed bool
}

func (w *codexTurnClientWriter) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	w.failed = w.failed || err != nil || n != len(data)
	return n, err
}

func (w *codexTurnClientWriter) WriteString(data string) (int, error) {
	n, err := w.ResponseWriter.WriteString(data)
	w.failed = w.failed || err != nil || n != len(data)
	return n, err
}

func observeCodexTurnResponse(resp *http.Response, snapshot *codexAccountTurnSnapshot, c *gin.Context) *codexTurnResponseObserver {
	if snapshot == nil || !validCodexTurnState(extractOpenAICodexTurnState(resp.Header)) {
		return nil
	}
	o := &codexTurnResponseObserver{ReadCloser: resp.Body, sse: isEventStreamResponse(resp.Header)}
	o.writer = &codexTurnClientWriter{ResponseWriter: c.Writer}
	c.Writer = o.writer
	resp.Body = o
	return o
}

func codexTurnSuccessfulEvent(data []byte) bool {
	if !gjson.ValidBytes(data) {
		return false
	}
	kind := gjson.GetBytes(data, "type").String()
	status := gjson.GetBytes(data, "response.status").String()
	return (kind == "response.completed" || kind == "response.done") &&
		(status == "" || status == "completed") &&
		!codexTurnHasError(data, "error") && !codexTurnHasError(data, "response.error")
}

func codexTurnHasError(data []byte, path string) bool {
	value := gjson.GetBytes(data, path)
	return value.Exists() && value.Type != gjson.Null
}

func (o *codexTurnResponseObserver) inspect(data []byte) {
	if !gjson.ValidBytes(data) {
		return
	}
	kind := gjson.GetBytes(data, "type").String()
	if kind == "error" || strings.HasPrefix(kind, "response.fail") || kind == "response.incomplete" || strings.HasPrefix(kind, "response.cancel") {
		o.failed = true
	}
	if codexTurnSuccessfulEvent(data) {
		o.succeeded = true
	}
}

func (o *codexTurnResponseObserver) Read(p []byte) (int, error) {
	n, err := o.ReadCloser.Read(p)
	if !o.failed {
		o.pending = append(o.pending, p[:n]...)
		if o.sse {
			for {
				end := bytes.IndexByte(o.pending, '\n')
				if end < 0 {
					break
				}
				line := bytes.TrimSpace(o.pending[:end])
				if bytes.HasPrefix(line, []byte("data:")) {
					o.inspect(bytes.TrimSpace(line[5:]))
				}
				o.pending = o.pending[end+1:]
			}
		}
		if len(o.pending) > 16*1024*1024 {
			o.failed, o.pending = true, nil
		}
		if err == io.EOF && !o.sse {
			// unary JSON 必须明确声明 completed；普通 200 JSON 不推断成功。
			o.succeeded = gjson.ValidBytes(o.pending) && gjson.GetBytes(o.pending, "status").String() == "completed" && !codexTurnHasError(o.pending, "error")
		}
	}
	if err != nil && err != io.EOF {
		o.failed = true
	}
	return n, err
}

func (o *codexTurnResponseObserver) successful() bool {
	return o != nil && o.succeeded && !o.failed && !o.writer.failed
}

func (o *codexTurnResponseObserver) restore(c *gin.Context) {
	if o != nil && c.Writer == o.writer {
		c.Writer = o.writer.ResponseWriter
	}
}
