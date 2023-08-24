// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package calltraceapi

import "golang.org/x/sys/unix"

type StackAddr struct {
	Addr   uint64
	Symbol string
}

type MsgCalltrace struct {
	Stack [unix.PERF_MAX_STACK_DEPTH]uint64
	Ret   int32
}
