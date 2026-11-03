//go:build unix

package main

import "syscall"

func peek(fd uintptr, buf []byte) (int, error) {
	n, _, err := syscall.Recvfrom(int(fd), buf, syscall.MSG_PEEK)
	return n, err
}
