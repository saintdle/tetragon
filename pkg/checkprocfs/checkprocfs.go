// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package checkprocfs

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/cilium/tetragon/pkg/bpf/hostpid"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/sirupsen/logrus"
)

// Check compares the pid of the running process (typically the agent) against
// reading self from the provided proc directory as a way to check whether the
// provided proc fs is indeed the host proc fs.
func Check() {

	selfPath := filepath.Join(option.Config.ProcFS, "self")
	procPidStr, err := os.Readlink(selfPath)
	if err != nil {
		logger.GetLogger().WithError(err).Info("failed to read self link")
		return
	}

	procPid, err := strconv.ParseInt(procPidStr, 0, 32)
	if err != nil {
		logger.GetLogger().WithError(err).Info("failed to convert pid")
		return
	}

	hostPid, err := hostpid.HostPID()
	if err != nil {
		logger.GetLogger().WithError(err).Info("failed retrieve host PID")
		return
	}

	if hostPid != int32(procPid) {
		logger.GetLogger().WithFields(logrus.Fields{
			"host-pid": hostPid,
			"proc-pid": procPid,
			"procfs":   option.Config.ProcFS,
		}).Warn("pid mismatch: Is procfs the host /proc?")
	}
}
