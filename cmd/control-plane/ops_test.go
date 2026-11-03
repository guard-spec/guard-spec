package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestLoadOpsConfig(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cfg, err := loadOpsConfig(env(nil))
	if err != nil || cfg.MetricsAddr != ":9091" || cfg.Retention.Days != 90 ||
		cfg.Retention.Interval != time.Hour || cfg.Retention.Batch != 5000 {
		t.Fatalf("defaults: %+v %v", cfg, err)
	}
	cfg, err = loadOpsConfig(env(map[string]string{"AUDIT_RETENTION_DAYS": "0", "METRICS_ADDR": "off"}))
	if err != nil || cfg.Retention.Days != 0 || cfg.MetricsAddr != "off" {
		t.Fatalf("%+v %v", cfg, err)
	}
	for _, bad := range []map[string]string{
		{"AUDIT_RETENTION_DAYS": "-1"}, {"AUDIT_RETENTION_DAYS": "x"},
		{"AUDIT_RETENTION_INTERVAL": "10s"}, {"AUDIT_RETENTION_BATCH": "0"},
	} {
		if _, err := loadOpsConfig(env(bad)); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestOptLimit(t *testing.T) {
	var req struct {
		A optLimit `json:"a"`
		B optLimit `json:"b"`
		C optLimit `json:"c"`
	}
	if err := json.Unmarshal([]byte(`{"a":5,"b":null}`), &req); err != nil {
		t.Fatal(err)
	}
	if !req.A.Set || *req.A.Value != 5 || !req.B.Set || req.B.Value != nil || req.C.Set {
		t.Errorf("%+v", req)
	}
	for _, bad := range []string{`{"a":-1}`, `{"a":1.5}`, `{"a":"5"}`, `{"a":3000000000}`} {
		if err := json.Unmarshal([]byte(bad), &req); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
