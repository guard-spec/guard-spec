// Command models downloads the ONNX models listed in models/manifest.yaml.
//
//	go run ./cmd/models pull [-dir models/cache] [-manifest models/manifest.yaml] [-models a,b]
//	go run ./cmd/models verify [-dir models/cache] [-models a,b]
//	go run ./cmd/models list
//
// Every file is checked against the SHA-256 pinned in the manifest; a mismatch
// is refused and the partial download removed. HF_TOKEN is sent when set (needed
// for gated repos such as protectai/deberta-v3-small-prompt-injection-v2).
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/promptshield/promptshield/internal/onnx"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dir := fs.String("dir", "models/cache", "directory the models are stored in (one sub-directory per model)")
	manifestPath := fs.String("manifest", "models/manifest.yaml", "manifest file")
	only := fs.String("models", "", "comma-separated model names (default: all)")
	_ = fs.Parse(os.Args[2:])

	m, err := onnx.LoadManifest(*manifestPath)
	if err != nil {
		fatal(err)
	}
	selected, explicit, err := selectModels(m, *only)
	if err != nil {
		fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	switch cmd {
	case "list":
		for _, mod := range m.Models {
			var size int64
			for _, f := range mod.Files {
				size += f.Size
			}
			gated := ""
			if mod.Gated {
				gated = " (gated: needs HF_TOKEN)"
			}
			if mod.Optional {
				gated += " (optional)"
			}
			fmt.Printf("%-36s %-10s %8.1f MB  %-11s %s@%s%s\n", mod.Name, mod.Kind, float64(size)/1e6, mod.License, mod.Repo, mod.Revision[:12], gated)
		}
	case "pull":
		token := os.Getenv("HF_TOKEN")
		p := &onnx.Puller{
			Client: &http.Client{Timeout: 60 * time.Minute},
			Token:  token,
			Log:    func(f string, a ...any) { fmt.Printf(f+"\n", a...) },
		}
		failed := false
		for _, mod := range selected {
			if mod.Optional && !explicit {
				fmt.Printf("%s: skipped, optional (pull it with -models %s)\n", mod.Name, mod.Name)
				continue
			}
			if mod.Gated && token == "" && !explicit {
				fmt.Printf("%s: skipped, %s is gated (accept its terms on huggingface.co and set HF_TOKEN)\n", mod.Name, mod.Repo)
				continue
			}
			if err := p.Pull(ctx, mod, *dir); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				failed = true
				continue
			}
			fmt.Printf("%s: ok (%s)\n", mod.Name, filepath.Join(*dir, mod.Name))
		}
		if failed {
			os.Exit(1)
		}
	case "verify":
		failed := false
		for _, mod := range selected {
			for _, f := range mod.Files {
				path := filepath.Join(*dir, mod.Name, f.Dest)
				if err := onnx.VerifyFile(path, f); err != nil {
					fmt.Printf("%s: %v\n", path, err)
					failed = true
				} else {
					fmt.Printf("%s: ok\n", path)
				}
			}
		}
		if failed {
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func selectModels(m *onnx.Manifest, only string) ([]*onnx.ManifestModel, bool, error) {
	if only == "" {
		out := make([]*onnx.ManifestModel, 0, len(m.Models))
		for i := range m.Models {
			out = append(out, &m.Models[i])
		}
		return out, false, nil
	}
	var out []*onnx.ManifestModel
	for _, name := range strings.Split(only, ",") {
		mod, ok := m.Find(strings.TrimSpace(name))
		if !ok {
			return nil, true, fmt.Errorf("model %q is not in the manifest", name)
		}
		out = append(out, mod)
	}
	return out, true, nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: models <pull|verify|list> [-dir models/cache] [-manifest models/manifest.yaml] [-models a,b]")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
