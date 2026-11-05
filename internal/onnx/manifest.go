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

// UnpinnedRevision is the placeholder revision of a model that is not on
// Hugging Face yet. It is only accepted for a model with mirrors; Pull skips
// Hugging Face for it and downloads from the mirrors (still verified against
// the pinned SHA-256).
const UnpinnedRevision = "0000000000000000000000000000000000000000"

// MirrorFilePlaceholder is replaced by a file's dest name in a mirror URL.
const MirrorFilePlaceholder = "{file}"

// Manifest lists the models that can be pulled (models/manifest.yaml).
type Manifest struct {
	Models []ManifestModel `yaml:"models"`
}

// ManifestModel is one version of a model, pinned to a Hugging Face commit.
// The same name may appear with several versions; it is installed in
// <dir>/<name>/<version>/.
type ManifestModel struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
	// Recommended marks the version used when only the name is given (and,
	// for the gateway, the default model of its kind).
	Recommended bool   `yaml:"recommended"`
	Kind        string `yaml:"kind"` // classifier or embedder
	Repo        string `yaml:"repo"`
	Revision    string `yaml:"revision"`
	// Mirrors are fallback URL templates tried in order after Hugging Face;
	// {file} is replaced by the file's dest name. HF_TOKEN is never sent to them.
	Mirrors    []string       `yaml:"mirrors"`
	License    string         `yaml:"license"`
	LicenseURL string         `yaml:"license_url"`
	Gated      bool           `yaml:"gated"`    // needs HF_TOKEN
	Optional   bool           `yaml:"optional"` // pulled only when named
	Files      []ManifestFile `yaml:"files"`
}

// Ref is "name@version".
func (m *ManifestModel) Ref() string { return m.Name + "@" + m.Version }

// Dir is the model's install directory under root: root/<name>/<version>.
func (m *ManifestModel) Dir(root string) string { return filepath.Join(root, m.Name, m.Version) }

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
	m, err := ParseManifest(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m, nil
}

// ParseManifest parses and validates manifest YAML.
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// validPathPart reports whether s can be one directory name.
func validPathPart(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, `/\@`) && strings.TrimSpace(s) == s
}

// Validate checks that every model is pinned and every file has a digest.
func (m *Manifest) Validate() error {
	seen := map[string]bool{}
	recommended := map[string]bool{}
	for _, mod := range m.Models {
		switch {
		case !validPathPart(mod.Name):
			return fmt.Errorf("model %q: invalid name", mod.Name)
		case !validPathPart(mod.Version):
			return fmt.Errorf("model %q: invalid or missing version %q", mod.Name, mod.Version)
		case seen[mod.Ref()]:
			return fmt.Errorf("model %s: duplicate name and version", mod.Ref())
		case mod.Recommended && recommended[mod.Name]:
			return fmt.Errorf("model %s: more than one recommended version of %s", mod.Ref(), mod.Name)
		case mod.Repo == "":
			return fmt.Errorf("model %s: missing repo", mod.Ref())
		case !isHex(mod.Revision, 40):
			return fmt.Errorf("model %s: revision must be a 40-char commit sha", mod.Ref())
		case mod.Revision == UnpinnedRevision && len(mod.Mirrors) == 0:
			return fmt.Errorf("model %s: an unpinned revision needs a mirror", mod.Ref())
		case mod.License == "":
			return fmt.Errorf("model %s: missing license", mod.Ref())
		case len(mod.Files) == 0:
			return fmt.Errorf("model %s: no files", mod.Ref())
		}
		seen[mod.Ref()] = true
		recommended[mod.Name] = recommended[mod.Name] || mod.Recommended
		for _, u := range mod.Mirrors {
			if !strings.HasPrefix(u, "https://") || !strings.Contains(u, MirrorFilePlaceholder) {
				return fmt.Errorf("model %s: mirror %q must be an https URL containing %s", mod.Ref(), u, MirrorFilePlaceholder)
			}
		}
		for _, f := range mod.Files {
			if f.Src == "" || f.Dest == "" || filepath.Base(f.Dest) != f.Dest || f.Dest == "." || f.Dest == ".." {
				return fmt.Errorf("model %s: bad file entry %+v", mod.Ref(), f)
			}
			if f.SHA256 == "" && f.GitSHA1 == "" {
				return fmt.Errorf("model %s file %s: needs sha256 or git_sha1", mod.Ref(), f.Src)
			}
			if f.SHA256 != "" && !isHex(f.SHA256, 64) {
				return fmt.Errorf("model %s file %s: bad sha256", mod.Ref(), f.Src)
			}
			if f.GitSHA1 != "" && (!isHex(f.GitSHA1, 40) || f.Size <= 0) {
				return fmt.Errorf("model %s file %s: git_sha1 needs 40 hex chars and a size", mod.Ref(), f.Src)
			}
			if f.SHA256 == "" && len(mod.Mirrors) > 0 {
				return fmt.Errorf("model %s file %s: files of a model with mirrors need sha256", mod.Ref(), f.Src)
			}
		}
	}
	return nil
}

// ParseRef splits "name" or "name@version"; version is "" without "@".
func ParseRef(ref string) (name, version string, err error) {
	ref = strings.TrimSpace(ref)
	name, version, hasAt := strings.Cut(ref, "@")
	if !validPathPart(name) || (hasAt && !validPathPart(version)) {
		return "", "", fmt.Errorf("invalid model reference %q (want name or name@version)", ref)
	}
	return name, version, nil
}

// Find returns the default version of the named model: the recommended one,
// else the first listed.
func (m *Manifest) Find(name string) (*ManifestModel, bool) {
	var first *ManifestModel
	for i := range m.Models {
		if m.Models[i].Name != name {
			continue
		}
		if m.Models[i].Recommended {
			return &m.Models[i], true
		}
		if first == nil {
			first = &m.Models[i]
		}
	}
	return first, first != nil
}

// FindVersion returns one version of a model.
func (m *Manifest) FindVersion(name, version string) (*ManifestModel, bool) {
	for i := range m.Models {
		if m.Models[i].Name == name && m.Models[i].Version == version {
			return &m.Models[i], true
		}
	}
	return nil, false
}

// Lookup resolves "name" (the default version) or "name@version".
func (m *Manifest) Lookup(ref string) (*ManifestModel, error) {
	name, version, err := ParseRef(ref)
	if err != nil {
		return nil, err
	}
	if version == "" {
		if mod, ok := m.Find(name); ok {
			return mod, nil
		}
		return nil, fmt.Errorf("model %q is not in the manifest", name)
	}
	if mod, ok := m.FindVersion(name, version); ok {
		return mod, nil
	}
	return nil, fmt.Errorf("model %s@%s is not in the manifest (see `models list --available`)", name, version)
}

// Defaults are the default version of every model name, in manifest order.
func (m *Manifest) Defaults() []*ManifestModel {
	var out []*ManifestModel
	done := map[string]bool{}
	for _, mod := range m.Models {
		if done[mod.Name] {
			continue
		}
		done[mod.Name] = true
		d, _ := m.Find(mod.Name)
		out = append(out, d)
	}
	return out
}

// Recommended is the recommended, non-optional model of a kind ("classifier",
// "embedder"), or nil.
func (m *Manifest) Recommended(kind string) *ManifestModel {
	for i := range m.Models {
		if mod := &m.Models[i]; mod.Kind == kind && mod.Recommended && !mod.Optional {
			return mod
		}
	}
	return nil
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

// Puller downloads manifest files: from Mirror (when set), then Hugging Face,
// then the model's mirrors, in that order. Every file is verified whatever
// its source.
type Puller struct {
	Client  *http.Client
	BaseURL string // default https://huggingface.co
	Token   string // HF_TOKEN, needed for gated repos; sent to Hugging Face only
	// Mirror is an optional base URL tried first, as <Mirror>/<name>/<version>/<file>
	// (MODELS_MIRROR): an internal mirror or a local file server.
	Mirror string
	Log    func(format string, args ...any)
}

// FileURL is the Hugging Face download URL of a file at the pinned revision.
func (p *Puller) FileURL(m *ManifestModel, f ManifestFile) string {
	base := p.BaseURL
	if base == "" {
		base = "https://huggingface.co"
	}
	return fmt.Sprintf("%s/%s/resolve/%s/%s", strings.TrimRight(base, "/"), m.Repo, m.Revision, f.Src)
}

// source is one place a file can be downloaded from.
type source struct {
	url  string
	auth bool // send HF_TOKEN
}

// sources lists the download URLs of a file, in the order they are tried.
func (p *Puller) sources(m *ManifestModel, f ManifestFile) []source {
	var out []source
	if p.Mirror != "" {
		out = append(out, source{url: fmt.Sprintf("%s/%s/%s/%s", strings.TrimRight(p.Mirror, "/"), m.Name, m.Version, f.Dest)})
	}
	if m.Revision != UnpinnedRevision {
		out = append(out, source{url: p.FileURL(m, f), auth: true})
	}
	for _, u := range m.Mirrors {
		out = append(out, source{url: strings.ReplaceAll(u, MirrorFilePlaceholder, f.Dest)})
	}
	return out
}

// Installed reports whether every file of m is in place under root and
// matches the manifest (the full SHA-256 check).
func Installed(m *ManifestModel, root string) bool {
	for _, f := range m.Files {
		if VerifyFile(filepath.Join(m.Dir(root), f.Dest), f) != nil {
			return false
		}
	}
	return true
}

// Pull installs m in root/<name>/<version>/. When every file is already there
// and verified it does nothing. Otherwise it builds the version in a temporary
// directory next to it, reusing verified files (from the install directory or
// from the pre-version layout root/<name>/<dest>) and downloading the rest,
// and renames that directory into place only when every file has verified.
// A failed pull leaves the previous state untouched.
func (p *Puller) Pull(ctx context.Context, m *ManifestModel, root string) error {
	final := m.Dir(root)
	if Installed(m, root) {
		p.logf("%s: present, verified", m.Ref())
		return nil
	}
	parent := filepath.Dir(final)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, "."+m.Version+".tmp-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }() // no-op after a successful rename
	for _, f := range m.Files {
		dest := filepath.Join(tmp, f.Dest)
		if p.reuse(m, f, dest, final, parent) {
			continue
		}
		sum, err := p.fetch(ctx, m, f, dest)
		if err != nil {
			return fmt.Errorf("%s/%s: %w", m.Ref(), f.Dest, err)
		}
		if f.SHA256 == "" {
			p.logf("%s/%s: verified by git_sha1; pin sha256: %s", m.Ref(), f.Dest, sum)
		} else {
			p.logf("%s/%s: downloaded, sha256 ok", m.Ref(), f.Dest)
		}
	}
	if err := os.Chmod(tmp, 0o755); err != nil { // MkdirTemp uses 0700
		return err
	}
	return replaceDir(tmp, final)
}

// reuse links or copies an already verified copy of f into dest.
func (p *Puller) reuse(m *ManifestModel, f ManifestFile, dest string, dirs ...string) bool {
	for _, d := range dirs {
		src := filepath.Join(d, f.Dest)
		if VerifyFile(src, f) != nil {
			continue
		}
		if err := linkOrCopy(src, dest); err != nil {
			p.logf("%s/%s: cannot reuse %s: %v", m.Ref(), f.Dest, src, err)
			continue
		}
		p.logf("%s/%s: present, verified", m.Ref(), f.Dest)
		return true
	}
	return false
}

// replaceDir moves tmp to final. An existing final (incomplete or corrupt,
// since a verified one is never replaced) is moved aside first and removed.
func replaceDir(tmp, final string) error {
	if _, err := os.Lstat(final); err == nil {
		old := tmp + ".old"
		if err := os.Rename(final, old); err != nil {
			return err
		}
		defer func() { _ = os.RemoveAll(old) }()
	}
	return os.Rename(tmp, final)
}

func linkOrCopy(src, dest string) error {
	if err := os.Link(src, dest); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func (p *Puller) logf(format string, args ...any) {
	if p.Log != nil {
		p.Log(format, args...)
	}
}

// fetch tries every source of f in turn. A digest mismatch from one source
// is reported like any other failure and the next source is tried.
func (p *Puller) fetch(ctx context.Context, m *ManifestModel, f ManifestFile, dest string) (string, error) {
	var errs []error
	srcs := p.sources(m, f)
	for i, s := range srcs {
		sum, err := p.download(ctx, m, f, s, dest)
		if err == nil {
			return sum, nil
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		errs = append(errs, fmt.Errorf("%s: %w", s.url, err))
		if i < len(srcs)-1 {
			p.logf("%s/%s: %s failed (%v); trying the next source", m.Ref(), f.Dest, s.url, err)
		}
	}
	if len(errs) == 0 {
		return "", errors.New("no download source")
	}
	return "", errors.Join(errs...)
}

func (p *Puller) download(ctx context.Context, m *ManifestModel, f ManifestFile, s source, dest string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return "", err
	}
	if s.auth && p.Token != "" {
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
	if s.auth && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
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
	if fi, err := fh.Stat(); err != nil {
		return err
	} else if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s: not a regular file", path)
	} else if f.Size > 0 && fi.Size() != f.Size {
		return fmt.Errorf("%w: size %d, want %d", ErrDigestMismatch, fi.Size(), f.Size)
	}
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
