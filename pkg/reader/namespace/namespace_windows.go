// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package namespace

import (
	"fmt"
	"os"
	"sync"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
)

type hostNamespaces struct {
	ns  *tetragon.Namespaces
	err error
}

var (
	// listNamespaces is the order how we read namespaces from /proc
	listNamespaces = [10]string{"uts", "ipc", "mnt", "pid", "pid_for_children", "net", "time", "time_for_children", "cgroup", "user"}

	hostNs     hostNamespaces
	hostNsOnce sync.Once

	// If kernel supports time namespace
	TimeNsSupport bool
)

func GetPidNsInode(pid uint32, nsStr string) (uint32, error) {
	return 0, fmt.Errorf("Not supported on Windows ")
}

func GetMyPidG() uint32 {
	return uint32(os.Getpid())
}

func GetHostNsInode(nsStr string) (uint32, error) {
	return GetPidNsInode(1, nsStr)
}

func GetSelfNsInode(nsStr string) (uint32, error) {
	return GetPidNsInode(uint32(GetMyPidG()), nsStr)
}

func IsMsgNsInHostMntUser(ns *processapi.MsgNamespaces) (bool, error) {
	return true, nil
}

func getConstNamespaces() (*tetragon.Namespaces, error) {
	retVal := &tetragon.Namespaces{
		Uts: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
		Ipc: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
		Mnt: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
		Pid: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
		PidForChildren: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
		Net: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
		Time: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
		TimeForChildren: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
		Cgroup: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
		User: &tetragon.Namespace{
			Inum:   1,
			IsHost: true,
		},
	}

	retVal.Time = nil
	retVal.TimeForChildren = nil

	return retVal, nil
}

func GetCurrentNamespace() *tetragon.Namespaces {
	ns, _ := getConstNamespaces()
	return ns
}

func GetMsgNamespaces(ns processapi.MsgNamespaces) (*tetragon.Namespaces, error) {
	return getConstNamespaces()
}
