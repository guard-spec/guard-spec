//go:build !onnx || !cgo

package onnx

// Available reports whether the ONNX Runtime backend is compiled in.
func Available() bool { return false }

// RuntimeVersion is the loaded ONNX Runtime version.
func RuntimeVersion() (string, error) { return "", ErrUnavailable }

// LibraryPath is the ONNX Runtime shared library that would be loaded.
func LibraryPath() string { return "" }

func newBackend(string, modelKind, Options) (tokenizer, session, error) {
	return nil, nil, ErrUnavailable
}

func probeCUDAProvider(int) error { return ErrUnavailable }

func loadedRuntimeVersion() string { return "" }
