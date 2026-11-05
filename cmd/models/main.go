// Command models downloads the ONNX models listed in models/manifest.yaml.
//
//	go run ./cmd/models pull   [flags] [name[@version] ...]
//	go run ./cmd/models verify [flags] [name[@version] ...]
//	go run ./cmd/models list   [flags] [--available]
//
// Flags: -dir models/cache, -manifest models/manifest.yaml (the copy built
// into the binary when that file does not exist), -models a,b@v (same as the
// arguments), -mirror URL (MODELS_MIRROR).
//
// A version lands in <dir>/<name>/<version>/. A name without a version is its
// recommended version; without any name, pull and verify take the recommended
// version of every non-optional model. Every file is checked against the
// SHA-256 pinned in the manifest, and a version is renamed into place only
// when all of its files verified. Sources are tried in order: -mirror, Hugging
// Face, the manifest's mirrors. HF_TOKEN is sent to Hugging Face only (needed
// for gated repos such as protectai/deberta-v3-small-prompt-injection-v2).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/guard-spec/guard-spec/internal/onnx"
	"github.com/guard-spec/guard-spec/internal/version"
	"github.com/guard-spec/guard-spec/models"
)

const defaultManifest = "models/manifest.yaml"

type options struct {
	dir, manifest, only, mirror string
	available                   bool
	refs                        []string
	manifestSet                 bool
}

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	cmd := os.Args[1]
	if version.IsFlag(cmd) {
		fmt.Println("models", version.String())
		return
	}
	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		usage(os.Stdout)
		return
	}
	opts, err := parseArgs(cmd, os.Args[2:])
	if err != nil {
		fatal(err)
	}
	m, err := loadManifest(opts)
	if err != nil {
		fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	code, err := run(ctx, cmd, opts, m, os.Stdout)
	if err != nil {
		fatal(err)
	}
	os.Exit(code)
}

// parseArgs reads flags and model references in any order.
func parseArgs(cmd string, args []string) (options, error) {
	var o options
	fset := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fset.StringVar(&o.dir, "dir", "models/cache", "directory the models are stored in (<dir>/<name>/<version>/)")
	fset.StringVar(&o.manifest, "manifest", defaultManifest, "manifest file (default: models/manifest.yaml, else the copy built into this binary)")
	fset.StringVar(&o.only, "models", "", "comma-separated model references, name or name@version (default: the recommended version of every non-optional model)")
	fset.StringVar(&o.mirror, "mirror", os.Getenv("MODELS_MIRROR"), "base URL tried before Hugging Face: <mirror>/<name>/<version>/<file> (env MODELS_MIRROR)")
	fset.BoolVar(&o.available, "available", false, "list: the models in the manifest instead of the installed ones")
	for {
		if err := fset.Parse(args); err != nil {
			return o, err
		}
		args = fset.Args()
		if len(args) == 0 {
			break
		}
		o.refs = append(o.refs, args[0])
		args = args[1:]
	}
	fset.Visit(func(f *flag.Flag) {
		if f.Name == "manifest" {
			o.manifestSet = true
		}
	})
	for _, r := range strings.Split(o.only, ",") {
		if r = strings.TrimSpace(r); r != "" {
			o.refs = append(o.refs, r)
		}
	}
	return o, nil
}

func loadManifest(o options) (*onnx.Manifest, error) {
	if !o.manifestSet {
		if _, err := os.Stat(o.manifest); errors.Is(err, fs.ErrNotExist) {
			m, err := onnx.ParseManifest(models.Manifest)
			if err != nil {
				return nil, fmt.Errorf("built-in manifest: %w", err)
			}
			return m, nil
		}
	}
	return onnx.LoadManifest(o.manifest)
}

// selectModels resolves the references; without any it returns the default
// version of every model, and explicit is false.
func selectModels(m *onnx.Manifest, refs []string) (sel []*onnx.ManifestModel, explicit bool, err error) {
	if len(refs) == 0 {
		return m.Defaults(), false, nil
	}
	for _, r := range refs {
		mod, err := m.Lookup(r)
		if err != nil {
			return nil, true, err
		}
		sel = append(sel, mod)
	}
	return sel, true, nil
}

func run(ctx context.Context, cmd string, o options, m *onnx.Manifest, out io.Writer) (int, error) {
	switch cmd {
	case "list":
		if len(o.refs) > 0 {
			return 2, errors.New("list takes no model names")
		}
		if o.available {
			listAvailable(m, out)
		} else {
			listInstalled(m, o.dir, out)
		}
		return 0, nil
	case "pull":
		sel, explicit, err := selectModels(m, o.refs)
		if err != nil {
			return 1, err
		}
		token := os.Getenv("HF_TOKEN")
		p := &onnx.Puller{
			Client: &http.Client{Timeout: 60 * time.Minute},
			Token:  token,
			Mirror: o.mirror,
			Log:    func(f string, a ...any) { _, _ = fmt.Fprintf(out, f+"\n", a...) },
		}
		failed := false
		for _, mod := range sel {
			if mod.Optional && !explicit {
				_, _ = fmt.Fprintf(out, "%s: skipped, optional (pull it with: models pull %s)\n", mod.Ref(), mod.Ref())
				continue
			}
			if mod.Gated && token == "" && !explicit {
				_, _ = fmt.Fprintf(out, "%s: skipped, %s is gated (accept its terms on huggingface.co and set HF_TOKEN)\n", mod.Ref(), mod.Repo)
				continue
			}
			if err := p.Pull(ctx, mod, o.dir); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				failed = true
				continue
			}
			_, _ = fmt.Fprintf(out, "%s: ok (%s)\n", mod.Ref(), mod.Dir(o.dir))
		}
		if failed {
			return 1, nil
		}
		return 0, nil
	case "verify":
		sel, explicit, err := selectModels(m, o.refs)
		if err != nil {
			return 1, err
		}
		failed := false
		for _, mod := range sel {
			if mod.Optional && !explicit {
				continue
			}
			for _, f := range mod.Files {
				path := filepath.Join(mod.Dir(o.dir), f.Dest)
				if err := onnx.VerifyFile(path, f); err != nil {
					_, _ = fmt.Fprintf(out, "%s: %v\n", path, err)
					failed = true
				} else {
					_, _ = fmt.Fprintf(out, "%s: ok\n", path)
				}
			}
		}
		if failed {
			return 1, nil
		}
		return 0, nil
	default:
		usage(os.Stderr)
		return 2, nil
	}
}

func modelSize(mod *onnx.ManifestModel) int64 {
	var size int64
	for _, f := range mod.Files {
		size += f.Size
	}
	return size
}

func flags(mod *onnx.ManifestModel) string {
	var s []string
	if mod.Recommended {
		s = append(s, "recommended")
	}
	if mod.Optional {
		s = append(s, "optional")
	}
	if mod.Gated {
		s = append(s, "gated: needs HF_TOKEN")
	}
	if len(s) == 0 {
		return ""
	}
	return " (" + strings.Join(s, ", ") + ")"
}

func listAvailable(m *onnx.Manifest, out io.Writer) {
	_, _ = fmt.Fprintf(out, "%-36s %-9s %-10s %9s  %-11s %s\n", "NAME", "VERSION", "KIND", "SIZE", "LICENSE", "SOURCE")
	for i := range m.Models {
		mod := &m.Models[i]
		src := mod.Repo + "@" + mod.Revision[:12]
		if mod.Revision == onnx.UnpinnedRevision {
			src = "mirror only (not on Hugging Face yet)"
		}
		_, _ = fmt.Fprintf(out, "%-36s %-9s %-10s %6.1f MB  %-11s %s%s\n",
			mod.Name, mod.Version, mod.Kind, float64(modelSize(mod))/1e6, mod.License, src, flags(mod))
	}
}

// listInstalled shows the versions under dir. It checks that the files are
// there with the right size; `verify` checks their SHA-256.
func listInstalled(m *onnx.Manifest, dir string, out io.Writer) {
	n := 0
	names := map[string]bool{}
	for i := range m.Models {
		mod := &m.Models[i]
		names[mod.Name] = true
		if state := installState(mod, mod.Dir(dir)); state != "" {
			_, _ = fmt.Fprintf(out, "%-36s %-9s %s%s\n", mod.Name, mod.Version, state, flags(mod))
			n++
		}
	}
	// The layout before versions: <dir>/<name>/<files>.
	for _, mod := range m.Defaults() {
		if installState(mod, filepath.Join(dir, mod.Name)) == "installed" {
			_, _ = fmt.Fprintf(out, "%-36s %-9s installed in the old layout (%s); `models pull %s` reuses it for %s\n",
				mod.Name, "-", filepath.Join(dir, mod.Name), mod.Ref(), mod.Dir(dir))
			n++
		}
	}
	// Versions on disk that this manifest does not know.
	var unknown []string
	for name := range names {
		entries, _ := os.ReadDir(filepath.Join(dir, name))
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			if _, ok := m.FindVersion(name, e.Name()); !ok {
				unknown = append(unknown, name+"@"+e.Name())
			}
		}
	}
	sort.Strings(unknown)
	for _, u := range unknown {
		_, _ = fmt.Fprintf(out, "%-46s not in this manifest\n", u)
		n++
	}
	if n == 0 {
		_, _ = fmt.Fprintf(out, "no models in %s; see `models list --available` and `models pull`\n", dir)
	}
}

// installState is "installed", "incomplete" or "" (nothing there).
func installState(mod *onnx.ManifestModel, d string) string {
	have := 0
	for _, f := range mod.Files {
		fi, err := os.Stat(filepath.Join(d, f.Dest))
		if err == nil && fi.Mode().IsRegular() && (f.Size == 0 || fi.Size() == f.Size) {
			have++
		}
	}
	switch {
	case have == len(mod.Files):
		return "installed"
	case have > 0:
		return "incomplete (run pull)"
	}
	return ""
}

func usage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `usage: models <pull|verify|list> [flags] [name[@version] ...]

  models pull                              recommended version of every non-optional model
  models pull guardspec-classifier@v3b     one version, into <dir>/<name>/<version>/
  models verify [name[@version] ...]       check the SHA-256 of installed files
  models list                              installed versions
  models list --available                  versions in the manifest

flags:
  -dir DIR        model directory (default models/cache)
  -manifest FILE  manifest (default models/manifest.yaml, else the built-in copy)
  -models a,b@v   same as naming them as arguments
  -mirror URL     tried before Hugging Face: URL/<name>/<version>/<file> (env MODELS_MIRROR)`)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
