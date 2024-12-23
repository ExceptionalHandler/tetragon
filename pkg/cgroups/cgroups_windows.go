// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package cgroups

import (
	"bytes"
	"fmt"
)

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

func DetectDeploymentMode() (uint32, error) {
	return uint32(DEPLOY_UNKNOWN), fmt.Errorf("not Supported on Windows")
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
