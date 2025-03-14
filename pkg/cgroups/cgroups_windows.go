// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package cgroups

import (
	"bytes"
	"fmt"
)

const (
	// Generic unset value that means undefined or not set
	CGROUP_UNSET_VALUE = 0

	// Max cgroup subsystems count that is used from BPF side
	// to define a max index for the default controllers on tasks.
	// For further documentation check BPF part.
	CGROUP_SUBSYS_COUNT = 15

	// The default hierarchy for cgroupv2
	CGROUP_DEFAULT_HIERARCHY = 0
)

type CgroupModeCode int

const (
	/* Cgroup Mode:
	 * https://systemd.io/CGROUP_DELEGATION/
	 * But this should work also for non-systemd environments: where
	 * only legacy or unified are available by default.
	 */
	CGROUP_UNDEF CgroupModeCode = iota
)

type DeploymentCode int

const (
	// Deployment modes
	DEPLOY_UNKNOWN    DeploymentCode = iota
	DEPLOY_K8S        DeploymentCode = 1  // K8s deployment
	DEPLOY_CONTAINER  DeploymentCode = 2  // Container docker, podman, etc
	DEPLOY_SD_SERVICE DeploymentCode = 10 // Systemd service
	DEPLOY_SD_USER    DeploymentCode = 11 // Systemd user session
)

func (op DeploymentCode) String() string {
	return [...]string{
		DEPLOY_UNKNOWN:    "unknown",
		DEPLOY_K8S:        "Kubernetes",
		DEPLOY_CONTAINER:  "Container",
		DEPLOY_SD_SERVICE: "systemd service",
		DEPLOY_SD_USER:    "systemd user session",
	}[op]
}

// DetectCgroupFSMagic() runs by default DetectCgroupMode()
// CgroupFsMagicStr() Returns "Cgroupv2" or "Cgroupv1" based on passed magic.
func CgroupFsMagicStr(magic uint64) string {
	return ""
}

func GetCgroupIdFromPath(cgroupPath string) (uint64, error) {
	return 0, fmt.Errorf("not Supported on Windows")
}

// DiscoverSubSysIds() Discover Cgroup SubSys IDs and indexes.
// of the corresponding controllers that we are interested
// in. We need this dynamic behavior since these controllers are
// compile config.
func DiscoverSubSysIds() error {
	return fmt.Errorf("could not detect Cgroup filesystem")
}

func GetDeploymentMode() DeploymentCode {
	return DEPLOY_UNKNOWN
}

func GetCgroupMode() CgroupModeCode {
	return CGROUP_UNDEF
}

func GetCgrpHierarchyID() uint32 {
	return 0
}

func GetCgrpv1SubsystemIdx() uint32 {
	return 0
}

func GetCgrpControllerName() string {
	return ""
}

func DetectCgroupMode() (CgroupModeCode, error) {
	return CGROUP_UNDEF, fmt.Errorf("not Supported on Windows")
}

func DetectDeploymentMode() (DeploymentCode, error) {
	return DEPLOY_UNKNOWN, fmt.Errorf("not Supported on Windows")
}

// DetectCgroupFSMagic() runs by default DetectCgroupMode()
// Return the Cgroupfs v1 or v2 that will be used by bpf programs
func DetectCgroupFSMagic() (uint64, error) {
	return CGROUP_UNSET_VALUE, fmt.Errorf("could not detect Cgroup filesystem Magic")
}

// CgroupNameFromCstr() Returns a Golang string from the passed C language format string.
func CgroupNameFromCStr(cstr []byte) string {
	i := bytes.IndexByte(cstr, 0)
	if i == -1 {
		i = len(cstr)
	}
	return string(cstr[:i])
}

func HostCgroupRoot() (string, error) {
	return "", fmt.Errorf("not Supported on Windows")
}

// CgroupIDFromPID returns the cgroup id for a given pid.
func CgroupIDFromPID(pid uint32) (uint64, error) {
	return 0, fmt.Errorf("cgroup mode undefined on Windows")
}

// it uses the cgroup id from the child.
func GetCgroupIDFromSubCgroup(p string) (uint64, error) {

	return 0, fmt.Errorf("cgroup mode undefined on Windows")
}
