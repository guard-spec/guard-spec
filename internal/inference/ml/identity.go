// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

package ml

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/guard-spec/guard-spec/internal/inference/fusion"
)

// modelIdentity is a generation's stable identity: unlike its id, which
// counts reloads in this process, it is the same in every process that runs
// the same models with the same detector configuration, and differs as soon
// as anything that changes a score differs. A cache of scores shared between
// gateway replicas keys on it (cmd/gateway/scan_cache_shared.go), so replicas
// with different models never share entries and a reload needs no flush.
//
// Hashing the model files takes a moment (about 130 MB for the default
// classifier and embedder), so it runs once per generation in the background;
// until it is done the identity is not known.
type modelIdentity struct {
	once sync.Once
	id   atomic.Pointer[string]
}

// identityDoc is what the identity hashes. The detector's code (L1 rules,
// sanitizer, built-in calibrations and exemplars) is not in it: the gateway
// adds a hash of its own binary.
type identityDoc struct {
	Version int             `json:"v"`
	Layers  [3]bool         `json:"layers"` // the active layers
	Fusion  string          `json:"fusion"`
	L1Floor float64         `json:"l1_floor"`
	Cascade *fusion.Cascade `json:"cascade,omitempty"`
	// L2 is the classifier's name and the SHA-256 of every file in its
	// directory (weights, tokenizer, calibration.json); L2Cal the calibration
	// in use, which may be a built-in one.
	L2      string           `json:"l2,omitempty"`
	L2Files string           `json:"l2_files,omitempty"`
	L2Cal   *CalibrationFile `json:"l2_cal,omitempty"`
	// L3Files hashes the embedder's directory.
	L3Files string `json:"l3_files,omitempty"`
}

// identityVersion changes when identityDoc does.
const identityVersion = 1

// Identity returns the running generation's model identity (a hex SHA-256)
// and true, or false while it is still being computed; the first call for a
// generation starts that.
func (l *Live) Identity() (string, bool) {
	g := l.acquire()
	defer g.inflight.Done()
	if p := g.identity.id.Load(); p != nil {
		return *p, true
	}
	g.identity.once.Do(func() {
		go func() {
			id := l.computeIdentity(g)
			g.identity.id.Store(&id)
		}()
	})
	return "", false
}

// computeIdentity hashes what g's scores depend on.
func (l *Live) computeIdentity(g *generation) string {
	s := l.stack
	doc := identityDoc{Version: identityVersion, Fusion: g.fusion, L1Floor: g.fuser.L1Floor()}
	doc.Layers = s.Active
	doc.Layers[fusion.L2] = g.l2 != nil
	if s.cfg.Cascade != nil && s.Active[fusion.L1] {
		doc.Cascade = s.cfg.Cascade
	}
	if g.l2 != nil {
		cal := g.l2.Cal
		doc.L2, doc.L2Files, doc.L2Cal = g.l2.Label(), hashDir(g.l2.Dir), &cal
	}
	if s.L3 != nil {
		doc.L3Files = s.l3Files()
	}
	b, _ := json.Marshal(doc)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// l3Files hashes the embedder directory once: it is shared by every
// generation.
func (s *Stack) l3Files() string {
	s.l3Once.Do(func() { s.l3Hash = hashDir(s.l3Dir) })
	return s.l3Hash
}

// hashDir hashes the names and contents of the regular files under dir, in
// name order. A directory that cannot be read hashes to its path and the
// error, so that two such processes still only match when they agree.
func hashDir(dir string) string {
	h := sha256.New()
	var names []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			names = append(names, path)
		}
		return nil
	})
	if err != nil {
		h.Write([]byte("unreadable\x00" + dir + "\x00" + err.Error()))
		return hex.EncodeToString(h.Sum(nil))
	}
	sort.Strings(names)
	for _, name := range names {
		rel, _ := filepath.Rel(dir, name)
		fh := sha256.New()
		f, err := os.Open(name)
		if err == nil {
			_, err = io.Copy(fh, f)
			_ = f.Close()
		}
		if err != nil {
			fh.Write([]byte("unreadable\x00" + err.Error()))
		}
		h.Write([]byte(filepath.ToSlash(rel) + "\x00" + hex.EncodeToString(fh.Sum(nil)) + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}
