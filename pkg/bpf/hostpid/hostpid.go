// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package hostpid

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/option"
	"golang.org/x/sys/unix"
)

type filter struct {
	fd     int32
	whence int32
	off    int64
}

type event struct {
	Pid int32
}

func readEvents(rd *perf.Reader) ([]*event, error) {
	rd.SetDeadline(time.Now())

	events := make([]*event, 0, 1)
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return events, nil
			}
			return nil, err
		}

		r := bytes.NewReader(record.RawSample)
		ev := event{}
		err = binary.Read(r, binary.LittleEndian, &ev)
		if err != nil {
			return nil, err
		}
		events = append(events, &ev)
	}
}

// HostPID uses a bpf program (bpf_gethostpid) to retrieve the host PID of the agent from the kernel.
// It uses a kprobe and issues a dummy lseek system call to do so.
// If something went wrong, it returns an error.
func HostPID() (int32, error) {
	objPath := path.Join(option.Config.HubbleLib, "bpf_gethostpid.o")
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return 0, err
	}

	col, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return 0, err
	}
	defer col.Close()

	filterMap, ok := col.Maps["tg_hpid_filter_map"]
	if !ok {
		return 0, fmt.Errorf("tg_hpid_filter_map not in collection")
	}

	eventMap, ok := col.Maps["tg_hpid_event_map"]
	if !ok {
		return 0, fmt.Errorf("tg_hpid_event_map not in collection")
	}

	lseekProg, ok := col.Programs["tg_hpid_hook"]
	if !ok {
		return 0, fmt.Errorf("gethostpid program not in collection")
	}

	zero := uint32(0)
	filterVal := filter{
		fd:     -1,
		off:    4343,
		whence: 5151,
	}
	err = filterMap.Put(zero, filterVal)
	if err != nil {
		return 0, err
	}

	lseek, err := arch.AddSyscallPrefix("sys_lseek")
	if err != nil {
		return 0, err
	}

	link, err := link.Kprobe(lseek, lseekProg, &link.KprobeOptions{})
	if err != nil {
		return 0, err
	}
	defer link.Close()

	rd, err := perf.NewReader(eventMap, os.Getpagesize())
	if err != nil {
		return 0, err
	}
	defer rd.Close()

	// trigger hook
	unix.Seek(int(filterVal.fd), filterVal.off, int(filterVal.whence))

	events, err := readEvents(rd)
	if len(events) != 1 {
		return 0, fmt.Errorf("received %d events instead of 1", len(events))
	}

	return events[0].Pid, nil
}
