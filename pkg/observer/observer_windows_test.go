// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"bytes"
	"encoding/binary"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/grpc/exec"
)

var (
	procMonDLL         = syscall.NewLazyDLL("C:\\git\\ebpf-for-windows\\x64\\Debug\\process_monitor_dll.dll")
	getEventFunc       = procMonDLL.NewProc("GetEvent")
	startEventListener = procMonDLL.NewProc("StartEventListener")
)

func TestLoadDLL(t *testing.T) {

	go func() {
		startEventListener.Call()
	}()

	time.Sleep(4 * time.Second)
	buf := make([]byte, 2048)
	getEventFunc.Call(uintptr(unsafe.Pointer(&buf[0])))

	op := buf[0]
	r := bytes.NewReader(buf)
	t.Log("op = ", op)
	m := processapi.MsgExecveEvent{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		t.Log("FAIL")
	}
	//ToDo: Function Name
	unix := &exec.MsgExecveEventUnix{}
	unix.Unix = &processapi.MsgExecveEventUnix{}
	unix.Unix.Msg = &m
	t.Log("Parent pid = ", unix.Unix.Msg.Parent.Pid)

}
