package main

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// watchClose calls cancel when the client closes conn. fasthttp does not read
// from a connection while its handler runs, and its request context is only
// cancelled at server shutdown, so a client that leaves while the gateway waits
// for the upstream would otherwise go unnoticed until the upstream timeout.
//
// The watcher peeks at the socket (MSG_PEEK) through the runtime poller: it
// consumes nothing, so a pipelined request stays in place for fasthttp. When
// bytes are waiting it stops, as it cannot tell more. stop must be called before
// fasthttp uses the connection again; it returns once the watcher let go.
// Connections that are not plain sockets (TLS) are not watched.
//
// A reset always cancels. End of stream (the client's FIN) cancels only when
// cancelOnEOF is set. A client that closed and one that only half-closed
// (shutdown(SHUT_WR)) and still waits for the answer send the same FIN, and the
// gateway cannot tell them apart without writing to the socket, which HTTP does
// not allow before the response. HTTP clients close fully, so cancelling is the
// default; CLIENT_HALF_CLOSE=wait serves half-closing clients instead, and the
// watcher then stops at the FIN and leaves the rest to the upstream timeout.
func watchClose(conn net.Conn, cancel func(), cancelOnEOF bool) (stop func()) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return func() {}
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		return func() {}
	}
	var stopped atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		closed := false
		buf := make([]byte, 1)
		_ = rc.Read(func(fd uintptr) bool {
			if stopped.Load() {
				return true
			}
			n, err := peek(fd, buf)
			switch {
			case errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EINTR):
				return false // nothing yet: wait for the socket to become readable
			case err != nil:
				closed = true // reset
			case n == 0:
				closed = cancelOnEOF // FIN: closed, or only half-closed
			}
			return true
		})
		if closed && !stopped.Load() {
			cancel()
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			stopped.Store(true)
			_ = conn.SetReadDeadline(time.Unix(1, 0)) // wakes the poller
			<-done
			_ = conn.SetReadDeadline(time.Time{})
		})
	}
}
