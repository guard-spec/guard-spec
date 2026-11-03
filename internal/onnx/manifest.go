package onnx

import (
	"context"
	"crypto/sha1" //nolint:gosec // git blob ids are SHA-1 by definition
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manifest lists the models that can be pulled (models/manifest.yaml).
type Manifest struct {
	Models []ManifestModel `yaml:"models"`
}

// ManifestModel is one model pinned to a Hugging Face commit.
type ManifestModel struct {
	Name       string         `yaml:"name"`
	Kind       string         `yaml:"kind"` // classifier or embedder
	Repo       string         `yaml:"repo"`
	Revision   string         `yaml:"revision"`
	License    string         `yaml:"license"`
	LicenseURL string         `yaml:"license_url"`
	Gated      bool           `yaml:"gated"`    // needs HF_TOKEN
	Optional   bool           `yaml:"optional"` // pulled only when named with -models
	Files      []ManifestFile `yaml:"files"`
}

// ManifestFile is one file of a model. SHA256 is required unless GitSHA1 is
// given (small files of gated repos, see the manifest header).
type ManifestFile struct {
	Src     string `yaml:"src"`
	Dest    string `yaml:"dest"`
	Size    int64  `yaml:"size"`
	SHA256  string `yaml:"sha256"`
	GitSHA1 string `yaml:"git_sha1"`
}

// LoadManifest reads and validates a manifest file.
func LoadManifest(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &m, nil
}

// Validate checks that every model is pinned and every file has a digest.
func (m *Manifest) Validate() error {
	seen := map[string]bool{}
	for _, mod := range m.Models {
		switch {
		case mod.Name == "" || strings.ContainsAny(mod.Name, `/\`) || mod.Name == "." || mod.Name == "..":
			return fmt.Errorf("model %q: invalid name", mod.Name)
		case seen[mod.Name]:
			return fmt.Errorf("model %q: duplicate name", mod.Name)
		case mod.Repo == "":
			return fmt.Errorf("model %q: missing repo", mod.Name)
		case !isHex(mod.Revision, 40):
			return fmt.Errorf("model %q: revision must be a 40-char commit sha", mod.Name)
		case mod.License == "":
			return fmt.Errorf("model %q: missing license", mod.Name)
		case len(mod.Files) == 0:
			return fmt.Errorf("model %q: no files", mod.Name)
		}
		seen[mod.Name] = true
		for _, f := range mod.Files {
			if f.Src == "" || f.Dest == "" || filepath.Base(f.Dest) != f.Dest || f.Dest == "." || f.Dest == ".." {
				return fmt.Errorf("model %q: bad file entry %+v", mod.Name, f)
			}
			if f.SHA256 == "" && f.GitSHA1 == "" {
				return fmt.Errorf("model %q file %s: needs sha256 or git_sha1", mod.Name, f.Src)
			}
			if f.SHA256 != "" && !isHex(f.SHA256, 64) {
				return fmt.Errorf("model %q file %s: bad sha256", mod.Name, f.Src)
			}
			if f.GitSHA1 != "" && (!isHex(f.GitSHA1, 40) || f.Size <= 0) {
				return fmt.Errorf("model %q file %s: git_sha1 needs 40 hex chars and a size", mod.Name, f.Src)
			}
		}
	}
	return nil
}

// Find returns the model with the given name.
func (m *Manifest) Find(name string) (*ManifestModel, bool) {
	for i := range m.Models {
		if m.Models[i].Name == name {
			return &m.Models[i], true
		}
	}
	return nil, false
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// ErrDigestMismatch means a downloaded or cached file does not match the manifest.
var ErrDigestMismatch = errors.New("digest mismatch")

// Puller downloads manifest files from Hugging Face.
type Puller struct {
	Client  *http.Client
	BaseURL string // default https://huggingface.co
	Token   string // HF_TOKEN, needed for gated repos
	Log     func(format string, args ...any)
}

// FileURL is the download URL of a file at the pinned revision.
func (p *Puller) FileURL(m *ManifestModel, f ManifestFile) string {
	base := p.BaseURL
	if base == "" {
		base = "https://huggingface.co"
	}
	return fmt.Sprintf("%s/%s/resolve/%s/%s", strings.TrimRight(base, "/"), m.Repo, m.Revision, f.Src)
}

// Pull fetches every file of m into dir/<m.Name>/. Files already present with
// the right digest are kept; anything else is downloaded to a temporary file,
// verified, and only then renamed into place.
func (p *Puller) Pull(ctx context.Context, m *ManifestModel, dir string) error {
	out := filepath.Join(dir, m.Name)
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	for _, f := range m.Files {
		dest := filepath.Join(out, f.Dest)
		if err := VerifyFile(dest, f); err == nil {
			p.logf("%s/%s: present, verified", m.Name, f.Dest)
			continue
		}
		sum, err := p.download(ctx, m, f, dest)
		if err != nil {
			return fmt.Errorf("%s/%s: %w", m.Name, f.Dest, err)
		}
		if f.SHA256 == "" {
			p.logf("%s/%s: verified by git_sha1; pin sha256: %s", m.Name, f.Dest, sum)
		} else {
			p.logf("%s/%s: downloaded, sha256 ok", m.Name, f.Dest)
		}
	}
	return nil
}

func (p *Puller) logf(format string, args ...any) {
	if p.Log != nil {
		p.Log(format, args...)
	}
}

func (p *Puller) download(ctx context.Context, m *ManifestModel, f ManifestFile, dest string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.FileURL(m, f), nil)
	if err != nil {
		return "", err
	}
	if p.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.Token)
	}
	client := p.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		if m.Gated {
			return "", fmt.Errorf("HTTP %d: %s is gated; accept its terms on huggingface.co and set HF_TOKEN", resp.StatusCode, m.Repo)
		}
		return "", fmt.Errorf("HTTP %d (set HF_TOKEN?)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(filepath.Dir(dest), "."+f.Dest+".part-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after a successful rename
	d := newDigester(f)
	n, err := io.Copy(io.MultiWriter(tmp, d), resp.Body)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	sum, err := d.check(n)
	if err != nil {
		return "", err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil { // CreateTemp uses 0600
		return "", err
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return "", err
	}
	return sum, nil
}

// VerifyFile checks a local file against its manifest entry.
func VerifyFile(path string, f ManifestFile) error {
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = fh.Close() }()
	d := newDigester(f)
	n, err := io.Copy(d, fh)
	if err != nil {
		return err
	}
	_, err = d.check(n)
	return err
}

// digester hashes a stream with SHA-256 and, when the manifest gives one, the
// git blob SHA-1 ("blob <size>\x00" + content). The git header needs the size
// up front, so it uses the manifest size and check() rejects any other length.
type digester struct {
	f     ManifestFile
	s256  hash.Hash
	gsha1 hash.Hash
}

func newDigester(f ManifestFile) *digester {
	d := &digester{f: f, s256: sha256.New()}
	if f.GitSHA1 != "" {
		d.gsha1 = sha1.New() //nolint:gosec
		d.gsha1.Write([]byte("blob " + strconv.FormatInt(f.Size, 10) + "\x00"))
	}
	return d
}

func (d *digester) Write(b []byte) (int, error) {
	d.s256.Write(b)
	if d.gsha1 != nil {
		d.gsha1.Write(b)
	}
	return len(b), nil
}

func (d *digester) check(n int64) (string, error) {
	sum := hex.EncodeToString(d.s256.Sum(nil))
	if d.f.Size > 0 && n != d.f.Size {
		return sum, fmt.Errorf("%w: size %d, want %d", ErrDigestMismatch, n, d.f.Size)
	}
	if d.f.SHA256 != "" && !strings.EqualFold(sum, d.f.SHA256) {
		return sum, fmt.Errorf("%w: sha256 %s, want %s", ErrDigestMismatch, sum, d.f.SHA256)
	}
	if d.gsha1 != nil {
		if got := hex.EncodeToString(d.gsha1.Sum(nil)); !strings.EqualFold(got, d.f.GitSHA1) {
			return sum, fmt.Errorf("%w: git_sha1 %s, want %s", ErrDigestMismatch, got, d.f.GitSHA1)
		}
	}
	return sum, nil
}
