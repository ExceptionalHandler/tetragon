// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

import (
	"github.com/cilium/tetragon/pkg/kernels"
)

// ExecObj returns the exec object based on the kernel version
func ExecObj() string {
	return ""
}

// GenericKprobeObjs returns the generic kprobe and generic retprobe objects
func GenericKprobeObjs() (string, string) {
	if EnableV61Progs() {
		return "", ""
	} else if kernels.MinKernelVersion("5.11") {
		return "", ""
	} else if EnableLargeProgs() {
		return "", ""
	}
	return "", ""
}

func EnableV61Progs() bool {
	return false
}

func EnableLargeProgs() bool {
	return false
}
