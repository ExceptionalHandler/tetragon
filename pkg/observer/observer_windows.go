// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"context"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/perf"
	"github.com/cilium/tetragon/pkg/api/readyapi"
)

var (
	procMonDLL         = syscall.NewLazyDLL("C:\\git\\ebpf-for-windows\\x64\\Debug\\process_monitor_dll.dll")
	getEventFunc       = procMonDLL.NewProc("GetEvent")
	startEventListener = procMonDLL.NewProc("StartEventListener")
)

func readNewRecord() (perf.Record, error) {
	buf := make([]byte, 2048)
	getEventFunc.Call(uintptr(unsafe.Pointer(&buf[0])))
	var record perf.Record
	record.CPU = 1
	record.LostSamples = 0
	record.Remaining = 1
	record.RawSample = buf
	return record, nil

}

func (k *Observer) RunEvents(stopCtx context.Context, ready func()) error {

	// Inform caller that we're about to start processing events.
	k.observerListeners(&readyapi.MsgTetragonReady{})
	ready()

	// We spawn go routine to read and process perf events,
	// connected with main app through eventsQueue channel.
	eventsQueue := make(chan *perf.Record, k.getRBQueueSize())

	// Listeners are ready and about to start reading from perf reader, tell
	// user everything is ready.
	k.log.Info("Listening for events...")

	// Start reading records from the perf array. Reads until the reader is closed.
	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()

	go func() {
		defer wg.Done()
		startEventListener.Call()
	}()

	go func() {
		defer wg.Done()
		time.Sleep(1 * time.Second)
		for stopCtx.Err() == nil {
			record, err := readNewRecord()
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
