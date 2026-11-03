package main

import "testing"

func TestDigest(t *testing.T) {
	if d := digest(""); d.SHA256 != nil || d.Bytes != nil || d.Content != nil {
		t.Errorf("empty body gave %+v, want NULLs", d)
	}
	d := digest("abc")
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if d.SHA256 == nil || *d.SHA256 != want || d.Bytes == nil || *d.Bytes != 3 {
		t.Errorf("digest(abc) = %v, %v", d.SHA256, d.Bytes)
	}
	// The hash covers the bytes as received; only the stored copy is cleaned.
	d = digest("a\x00b\xff")
	if *d.Bytes != 4 || *d.Content != "a�b�" {
		t.Errorf("content = %q, bytes = %d", *d.Content, *d.Bytes)
	}
}
