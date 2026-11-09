//go:build onnx && cgo

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
)

// TestCodeLogThroughGateway posts benign code and logs as tool output through
// the real request paths with the model layers (L1+L2+L3, logreg, v3b) and
// writes one JSON line per request: a measurement harness for false
// positives on tool output (RF-476b4d30). It runs only when CODELOG_CORPUS
// names a JSONL file of {id, text} rows; CODELOG_OUT is the output file and
// CODELOG_PATHS a comma list of messages, chat, scan and user (default
// messages,chat,scan).
func TestCodeLogThroughGateway(t *testing.T) {
	corpus := os.Getenv("CODELOG_CORPUS")
	if corpus == "" {
		t.Skip("CODELOG_CORPUS not set")
	}
	paths := strings.Split(os.Getenv("CODELOG_PATHS"), ",")
	if paths[0] == "" {
		paths = []string{"messages", "chat", "scan"}
	}
	runner := benchStack(t, [3]bool{true, true, true})
	rows := readCodeLogCorpus(t, corpus)
	out, err := os.Create(os.Getenv("CODELOG_OUT"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	var mu sync.Mutex
	write := func(v any) {
		b, _ := json.Marshal(v)
		mu.Lock()
		defer mu.Unlock()
		_, _ = out.Write(append(b, '\n'))
	}

	up := newFakeUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/messages") {
			anthropicJSON(w, messageResponse(`{"type":"text","text":"ok"}`))
			return
		}
		okUpstream(w, r)
	})
	const workers = 4
	jobs := make(chan codeLogRow)
	var wg sync.WaitGroup
	for range workers {
		withRunner := func(gw *gateway) { gw.runner = runner }
		ant := startGateway(t, "", func(gw *gateway) { withAnthropic(up.URL)(gw); withRunner(gw) })
		oai := startGateway(t, up.URL, withRunner)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range jobs {
				for _, p := range paths {
					write(codeLogPost(t, p, ant, oai, r))
				}
			}
		}()
	}
	for _, r := range rows {
		jobs <- r
	}
	close(jobs)
	wg.Wait()
}

type codeLogResult struct {
	ID       string   `json:"id"`
	Path     string   `json:"path"`
	Status   int      `json:"status"`
	Blocked  bool     `json:"blocked"`
	Score    float64  `json:"score"`
	L1       float64  `json:"l1"`
	L2       float64  `json:"l2"`
	L3       float64  `json:"l3"`
	Category string   `json:"category"`
	Rules    []string `json:"rules"`
	Anomaly  float32  `json:"anomaly"`
	Source   string   `json:"source"`
	Error    string   `json:"error,omitempty"`
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func codeLogPost(t *testing.T, path string, ant, oai *harness, r codeLogRow) codeLogResult {
	res := codeLogResult{ID: r.ID, Path: path}
	text := jsonString(r.Text)
	var h *harness
	var url, body string
	switch path {
	case "messages":
		h, url = ant, "/v1/messages"
		body = `{"model":"claude-x","max_tokens":64,"messages":[` +
			`{"role":"user","content":"Look at this file and tell me what it does."},` +
			`{"role":"assistant","content":[{"type":"tool_use","id":"toolu_1","name":"Read","input":{"file_path":"/repo/x"}}]},` +
			`{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":` + text + `}]}]}`
	case "user":
		h, url = ant, "/v1/messages"
		body = `{"model":"claude-x","max_tokens":64,"messages":[{"role":"user","content":` +
			jsonString("Why does this fail?\n\n"+r.Text) + `}]}`
	case "chat":
		h, url = oai, "/v1/chat/completions"
		body = `{"model":"gpt-x","messages":[` +
			`{"role":"user","content":"Look at this file and tell me what it does."},` +
			`{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{\"path\":\"/repo/x\"}"}}]},` +
			`{"role":"tool","tool_call_id":"call_1","content":` + text + `}]}`
	case "scan":
		h, url = oai, "/guardrail/scan"
		body = `{"documents":[{"id":"d","source":"tool","content":` + text + `}]}`
	default:
		t.Fatalf("unknown path %q", path)
	}
	before := h.rowCount()
	req, _ := http.NewRequest("POST", h.url+url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", "test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	var scan struct {
		Blocked bool `json:"blocked"`
	}
	if path == "scan" {
		_ = json.NewDecoder(resp.Body).Decode(&scan)
	}
	_ = resp.Body.Close()
	res.Status = resp.StatusCode
	h.gw.audit.wait()
	e, ok := h.rowAfter(before)
	if !ok {
		res.Error = "no audit row"
		return res
	}
	res.Blocked = e.Action == actionBlock
	if path == "scan" {
		res.Blocked = scan.Blocked
	}
	res.Source, res.Anomaly = e.SourceRole, e.Report.AnomalyScore
	sc := e.Scores
	if path != "user" && e.Indirect.Source != "" {
		sc = e.Indirect.Scores
		res.Score = e.Indirect.Score
	} else {
		res.Score = float64(sc.Injection.Confidence)
	}
	if d := sc.Injection.Detail; d != nil {
		res.L1, res.L2, res.L3, res.Category, res.Rules = d.L1, d.L2, d.L3, d.Category, d.Rules
	}
	return res
}

func (h *harness) rowCount() int {
	h.rec.mu.Lock()
	defer h.rec.mu.Unlock()
	return len(h.rec.rows)
}

func (h *harness) rowAfter(n int) (requestEntry, bool) {
	h.rec.mu.Lock()
	defer h.rec.mu.Unlock()
	if len(h.rec.rows) <= n {
		return requestEntry{}, false
	}
	return h.rec.rows[len(h.rec.rows)-1], true
}
