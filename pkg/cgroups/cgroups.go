// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgroups

import (
	"sync"
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
	CGROUP_UNDEF   CgroupModeCode = iota
	CGROUP_LEGACY  CgroupModeCode = 1
	CGROUP_HYBRID  CgroupModeCode = 2
	CGROUP_UNIFIED CgroupModeCode = 3
)

type DeploymentCode int

type deploymentEnv struct {
	id       DeploymentCode
	str      string
	endsWith string
}

const (
	// Deployment modes
	DEPLOY_UNKNOWN    DeploymentCode = iota
	DEPLOY_K8S        DeploymentCode = 1  // K8s deployment
	DEPLOY_CONTAINER  DeploymentCode = 2  // Container docker, podman, etc
	DEPLOY_SD_SERVICE DeploymentCode = 10 // Systemd service
	DEPLOY_SD_USER    DeploymentCode = 11 // Systemd user session
)

type CgroupController struct {
	Id     uint32 // Hierarchy unique ID
	Idx    uint32 // Cgroup SubSys index
	Name   string // Controller name
	Active bool   // Will be set to true if controller is set and active
}

var (
	// Path where default cgroupfs is mounted
	defaultCgroupRoot = "/sys/fs/cgroup"

	/* Cgroup controllers that we are interested in
	 * are usually the ones that are setup by systemd
	 * or other init programs.
	 */
	CgroupControllers = []CgroupController{
		{Name: "memory"}, // Memory first
		{Name: "pids"},   // pids second
		{Name: "cpuset"}, // fallback
	}

	cgroupv2Hierarchy = "0::"

	/* Ordered from nested to top cgroup parents
	 * For k8s we check also config k8s flags.
	 */
	deployments = []deploymentEnv{
		{id: DEPLOY_K8S, str: "kube"},
		{id: DEPLOY_CONTAINER, str: "docker"},
		{id: DEPLOY_CONTAINER, str: "podman"},
		{id: DEPLOY_CONTAINER, str: "libpod"},
		// If Tetragon is running as a systemd service, its
		// cgroup path will end with .service
		{id: DEPLOY_SD_SERVICE, endsWith: ".service"},
		{id: DEPLOY_SD_USER, str: "user.slice"},
	}

	detectDeploymentOnce sync.Once
	deploymentMode       DeploymentCode

	detectCgrpModeOnce sync.Once
	cgroupMode         CgroupModeCode

	detectCgroupFSOnce sync.Once
	cgroupFSPath       string
	cgroupFSMagic      uint64

	// Cgroup Migration Path
	findMigPath       sync.Once
	cgrpMigrationPath string

	// Cgroup Tracking Hierarchy
	cgrpHierarchy      uint32 // 0 in case of cgroupv2
	cgrpv1SubsystemIdx uint32 // Not set in case of cgroupv2
)

func (code CgroupModeCode) String() string {
	return [...]string{
		CGROUP_UNDEF:   "undefined",
		CGROUP_LEGACY:  "Legacy mode (Cgroupv1)",
		CGROUP_HYBRID:  "Hybrid mode (Cgroupv1 and Cgroupv2)",
		CGROUP_UNIFIED: "Unified mode (Cgroupv2)",
	}[code]
}

func (op DeploymentCode) String() string {
	return [...]string{
		DEPLOY_UNKNOWN:    "unknown",
		DEPLOY_K8S:        "Kubernetes",
		DEPLOY_CONTAINER:  "Container",
		DEPLOY_SD_SERVICE: "systemd service",
		DEPLOY_SD_USER:    "systemd user session",
	}[op]
}

func GetCgroupFSMagic() uint64 {
	return cgroupFSMagic
}

func GetCgroupFSPath() string {
	return cgroupFSPath
}

type FileHandle struct {
	Id uint64
}
