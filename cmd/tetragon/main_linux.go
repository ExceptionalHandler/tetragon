// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"path"

	"github.com/cilium/tetragon/pkg/alignchecker"
	"github.com/cilium/tetragon/pkg/checkprocfs"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/reader/proc"
)

func logCurrentSecurityContext() {
	proc.LogCurrentSecurityContext()
}

func initHostNamespaces() error {
	_, err := namespace.InitHostNamespace()
	return err
}

func checkProcFS() {
	checkprocfs.Check()
}

func initCachedBTF(lib, btf string) error {
	return btf.InitCachedBTF(lib, btf)
}

func checkStructAlignments() error {
	path := path.Join(option.Config.HubbleLib, "bpf_alignchecker.o")
	return alignchecker.CheckStructAlignments(path)
}
