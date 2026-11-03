//go:build !unix

package main

// peek is not implemented here: reporting waiting data stops the watcher at
// once, and the upstream timeout bounds a request whose client left.
func peek(uintptr, []byte) (int, error) {
	return 1, nil
}
