// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/api/readyapi"
	"github.com/cilium/tetragon/pkg/bpf"
)

type Record struct {
	// The CPU this record was generated on.
	CPU int

	// The data submitted via bpf_perf_event_output.
	// Due to a kernel bug, this can contain between 0 and 7 bytes of trailing
	// garbage from the ring depending on the input sample's length.
	RawSample []byte

	// The number of samples which could not be output, since
	// the ring buffer was full.
	LostSamples uint64

	// The minimum number of bytes remaining in the per-CPU buffer after this Record has been read.
	// Negative for overwritable buffers.
	Remaining int
}

type RecordStruct struct {
	execEvent processapi.MsgExecveEvent
	process   processapi.MsgProcess
}

func getRecordFromProcInfo(process_info *bpf.ProcessInfo, command_map *ebpf.Map) (Record, error) {
	var record Record
	var procEvent RecordStruct
	procEvent.execEvent.Common.Op = ops.MSG_OP_EXECVE
	procEvent.execEvent.Parent.Pid = process_info.CreatingProcessId
	procEvent.process.PID = process_info.ProcessId
	procEvent.process.Flags = 1
	procEvent.process.NSPID = 0
	procEvent.process.Size = uint32(unsafe.Offsetof(procEvent.process.Filename))
	procEvent.process.Ktime = process_info.CreationTime
	var path [1024]uint16
	command_map.Lookup(process_info.ProcessId, &path)
	procEvent.process.Filename = windows.UTF16ToString(path[:])

	procEvent.process.Size += uint32(len(procEvent.process.Filename))

	copy(record.RawSample, *(*[]byte)(unsafe.Pointer(&procEvent)))
	return record, nil
}

func (k *Observer) RunEvents(stopCtx context.Context, ready func()) error {
	coll := bpf.GetExecCollection()
	if coll == nil {
		return fmt.Errorf("Exec Preloaded collection is nil")
	}
	commandline_map := coll.Maps["command_map"]
	ringBufMap := coll.Maps["process_ringbuf"]
	reader := bpf.GetNewWindowsRingBufReader()
	err := reader.Init(ringBufMap.FD(), int(ringBufMap.MaxEntries()))
	if err != nil {
		return fmt.Errorf("Failed initing rinbuf reader", err)
	}
	// Inform caller that we're about to start processing events.
	k.observerListeners(&readyapi.MsgTetragonReady{})
	ready()

	// We spawn go routine to read and process perf events,
	// connected with main app through eventsQueue channel.
	eventsQueue := make(chan *Record, k.getRBQueueSize())

	// Listeners are ready and about to start reading from perf reader, tell
	// user everything is ready.
	k.log.Info("Listening for events...")

	// Start reading records from the perf array. Reads until the reader is closed.
	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()

	go func() {
		defer wg.Done()
	}()

	go func() {
		defer wg.Done()

		for stopCtx.Err() == nil {
			procInfo, err := reader.GetNextProcess()
			if err != nil {
				k.log.WithField("NewError ", 0).WithError(err).Warn("Reading bpf events failed")
				break
			}
			if procInfo.Operation != 0 {
				continue
			}
			record, err := getRecordFromProcInfo(procInfo, commandline_map)
			if err != nil {
				if stopCtx.Err() == nil {
					RingbufErrors.Inc()
					errorCnt := getCounterValue(RingbufErrors)
					k.log.WithField("errors", errorCnt).WithError(err).Warn("Reading bpf events failed")
				}
			} else {
				if len(record.RawSample) > 0 {
					select {
					case eventsQueue <- &record:
					default:
						// eventsQueue channel is full, drop the event
						queueLost.Inc()
					}
					RingbufReceived.Inc()
				}

				if record.LostSamples > 0 {
					RingbufLost.Add(float64(record.LostSamples))
				}
			}
		}
	}()

	// Start processing records from perf.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case event := <-eventsQueue:
				k.receiveEvent(event.RawSample)
				queueReceived.Inc()
			case <-stopCtx.Done():
				k.log.WithError(stopCtx.Err()).Infof("Listening for events completed.")
				k.log.Debugf("Unprocessed events in RB queue: %d", len(eventsQueue))
				return
			}
		}
	}()

	// Loading default program consumes some memory lets kick GC to give
	// this back to the OS (K8s).
	go func() {
		runtime.GC()
	}()

	// Wait for context to be cancelled and then stop.
	<-stopCtx.Done()
	return nil
}
