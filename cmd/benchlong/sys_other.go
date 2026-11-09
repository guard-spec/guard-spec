//go:build !unix

package main

// cpuSeconds is not measured on this platform.
func cpuSeconds() float64 { return 0 }
