package ml

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/giaplee/guard-spec/internal/onnx"
)

// TestDefaultL2DirOrder: v3 is the default L2, falling back to v2, v1, then v0.
func TestDefaultL2DirOrder(t *testing.T) {
	root := t.TempDir()
	if got := DefaultL2Dir(root); got != "" {
		t.Fatalf("empty model dir: got %q", got)
	}
	install := func(sub string) string {
		d := filepath.Join(root, sub)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, onnx.ConfigFile), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		return d
	}
	for _, step := range []struct{ install, want string }{
		{L2DefaultV0, L2DefaultV0},
		{L2DefaultV1, L2DefaultV1},
		{L2DefaultV2, L2DefaultV2},
		{L2DefaultV3, L2DefaultV3},
	} {
		install(step.install)
		if got, want := DefaultL2Dir(root), filepath.Join(root, step.want); got != want {
			t.Errorf("after installing %s: got %q, want %q", step.install, got, want)
		}
	}
}
