// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors/unloader"
)

// AttachFunc is the type for the various attachment functions. The function is
// given the program and it's up to it to close it.
type AttachFunc func(*ebpf.Collection, *ebpf.CollectionSpec, *ebpf.Program, *ebpf.ProgramSpec) (unloader.Unloader, error)

type OpenFunc func(*ebpf.CollectionSpec) error

type LoadOpts struct {
	Attach AttachFunc
	Open   OpenFunc
}

func linkPinPath(bpfDir string, load *Program, extra ...string) string {
	pinPath := filepath.Join(bpfDir, load.PinPath, "link")
	if len(extra) != 0 {
		pinPath = pinPath + "_" + strings.Join(extra, "_")
	}
	return pinPath
}

func linkPin(lnk link.Link, bpfDir string, load *Program, extra ...string) error {
	// pinned link is not supported
	if !bpf.HasLinkPin() {
		return nil
	}

	pinPath := linkPinPath(bpfDir, load, extra...)

	err := lnk.Pin(pinPath)
	if err != nil {
		return fmt.Errorf("pinning link '%s' failed: %w", pinPath, err)
	}
	return nil
}

func RawAttach(targetFD int) AttachFunc {
	return RawAttachWithFlags(targetFD, 0)
}

func RawAttachWithFlags(targetFD int, flags uint32) AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		return nil, fmt.Errorf("windows not supported")
	}
}

func TracepointAttach(load *Program, bpfDir string) AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		return nil, fmt.Errorf("windows not supported")
	}
}

func RawTracepointAttach(load *Program) AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		return nil, fmt.Errorf("windows not supported")

	}
}

func disableProg(coll *ebpf.CollectionSpec, name string) {
	if spec, ok := coll.Programs[name]; ok {
		spec.Type = ebpf.UnspecifiedProgram
	}
}

func KprobeOpen(load *Program) OpenFunc {
	return func(coll *ebpf.CollectionSpec) error {
		// The generic_kprobe_override program is part of bpf_generic_kprobe.o object,
		// so let's disable it if the override is not configured. Otherwise it gets
		// loaded and bpftool will show it.
		if !load.Override {
			disableProg(coll, "generic_kprobe_override")
			disableProg(coll, "generic_fmodret_override")
		} else {
			if load.OverrideFmodRet {
				spec, ok := coll.Programs["generic_fmodret_override"]
				if !ok {
					return fmt.Errorf("failed to find generic_fmodret_override")
				}
				spec.AttachTo = load.Attach
				disableProg(coll, "generic_kprobe_override")
			} else {
				disableProg(coll, "generic_fmodret_override")
			}
		}
		return nil
	}
}

func kprobeAttach(load *Program, prog *ebpf.Program, spec *ebpf.ProgramSpec,
	symbol string, bpfDir string, extra ...string) (unloader.Unloader, error) {
	return nil, fmt.Errorf("windows not supported")
}

func windowsAttach(load *Program, prog *ebpf.Program, spec *ebpf.ProgramSpec,
	symbol string, bpfDir string, extra ...string) (unloader.Unloader, error) {

	link, err := link.AttachRawLink(link.RawLinkOptions{
		Program: prog,
		Attach:  ebpf.AttachWindowsProcess,
	})
	if err != nil {
		return nil, err
	}
	return unloader.ChainUnloader{
		unloader.ProgUnloader{
			Prog: prog,
		},
		unloader.LinkUnloader{
			Link: link,
		},
	}, nil

}

func kprobeAttachOverride(load *Program, bpfDir string,
	coll *ebpf.Collection, collSpec *ebpf.CollectionSpec) error {

	spec, ok := collSpec.Programs["generic_kprobe_override"]
	if !ok {
		return fmt.Errorf("spec for generic_kprobe_override program not found")
	}

	prog, ok := coll.Programs["generic_kprobe_override"]
	if !ok {
		return fmt.Errorf("program generic_kprobe_override not found")
	}

	prog, err := prog.Clone()
	if err != nil {
		return fmt.Errorf("failed to clone generic_kprobe_override program: %w", err)
	}

	pinPath := filepath.Join(bpfDir, load.PinPath, "prog_override")

	if err := prog.Pin(pinPath); err != nil {
		return fmt.Errorf("pinning '%s' to '%s' failed: %w", load.Label, pinPath, err)
	}

	load.unloaderOverride, err = kprobeAttach(load, prog, spec, load.Attach, bpfDir, "override")
	if err != nil {
		logger.GetLogger().Warnf("Failed to attach override program: %w", err)
	}

	return nil
}

func fmodretAttachOverride(load *Program, bpfDir string,
	coll *ebpf.Collection, collSpec *ebpf.CollectionSpec) error {

	return fmt.Errorf("windows not supported")

}

func WindowsAttach(load *Program, bpfDir string) AttachFunc {
	return func(coll *ebpf.Collection, collSpec *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		return windowsAttach(load, prog, spec, load.Attach, bpfDir)
	}
}

func KprobeAttach(load *Program, bpfDir string) AttachFunc {
	return func(coll *ebpf.Collection, collSpec *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		if load.Override {
			if load.OverrideFmodRet {
				if err := fmodretAttachOverride(load, bpfDir, coll, collSpec); err != nil {
					return nil, err
				}
			} else {
				if err := kprobeAttachOverride(load, bpfDir, coll, collSpec); err != nil {
					return nil, err
				}
			}
		}

		return kprobeAttach(load, prog, spec, load.Attach, bpfDir)
	}
}

func UprobeAttach(load *Program) AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
		return nil, fmt.Errorf("windows not supported")

	}
}

func MultiUprobeAttach(load *Program) AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
		return nil, fmt.Errorf("windows not supported")

	}
}

func NoAttach() AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, _ *ebpf.ProgramSpec) (unloader.Unloader, error) {
		return unloader.ChainUnloader{
			unloader.ProgUnloader{
				Prog: prog,
			},
		}, nil
	}
}

func TracingAttach() AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
		return nil, fmt.Errorf("windows not supported")
	}
}

func LSMOpen(load *Program) OpenFunc {
	return func(coll *ebpf.CollectionSpec) error {
		for _, prog := range coll.Programs {
			if prog.AttachType == ebpf.AttachLSMMac {
				prog.AttachTo = load.Attach
			} else {
				return fmt.Errorf("Only AttachLSMMac is supported for generic_lsm programs")
			}
		}
		return nil
	}
}

func LSMAttach() AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
		return nil, fmt.Errorf("windows not supported")
	}
}

func MultiKprobeAttach(load *Program, bpfDir string) AttachFunc {
	return func(coll *ebpf.Collection, collSpec *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {
		return nil, fmt.Errorf("windows not supported")

	}
}

func LoadTracepointProgram(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: TracepointAttach(load, bpfDir),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadRawTracepointProgram(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: RawTracepointAttach(load),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadKprobeProgram(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: KprobeAttach(load, bpfDir),
		Open:   KprobeOpen(load),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadWindowsProgram(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: WindowsAttach(load, bpfDir),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func KprobeAttachMany(load *Program, syms []string, bpfDir string) AttachFunc {
	return func(_ *ebpf.Collection, _ *ebpf.CollectionSpec,
		prog *ebpf.Program, spec *ebpf.ProgramSpec) (unloader.Unloader, error) {

		unloader := unloader.ChainUnloader{
			unloader.ProgUnloader{
				Prog: prog,
			},
		}

		for idx := range syms {
			un, err := kprobeAttach(load, prog, spec, syms[idx], bpfDir, fmt.Sprintf("%d_%s", idx, syms[idx]))
			if err != nil {
				return nil, err
			}

			unloader = append(unloader, un)
		}
		return unloader, nil
	}
}

func LoadKprobeProgramAttachMany(bpfDir string, load *Program, syms []string, verbose int) error {
	opts := &LoadOpts{
		Attach: KprobeAttachMany(load, syms, bpfDir),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadUprobeProgram(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: UprobeAttach(load),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadMultiKprobeProgram(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: MultiKprobeAttach(load, bpfDir),
		Open:   KprobeOpen(load),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadFmodRetProgram(bpfDir string, load *Program, progName string, verbose int) error {
	return fmt.Errorf("windows not supported")
}

func LoadTracingProgram(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: TracingAttach(),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadLSMProgram(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: LSMAttach(),
		Open:   LSMOpen(load),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadLSMProgramSimple(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: LSMAttach(),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func LoadMultiUprobeProgram(bpfDir string, load *Program, verbose int) error {
	opts := &LoadOpts{
		Attach: MultiUprobeAttach(load),
	}
	return loadProgram(bpfDir, load, opts, verbose)
}

func slimVerifierError(errStr string) string {
	// The error is potentially up to 'verifierLogBufferSize' bytes long,
	// and most of it is not interesting. For a user-friendly output, we'll
	// only keep the first and last N lines.

	nLines := 30
	headLines := 0
	headEnd := 0

	for ; headEnd < len(errStr); headEnd++ {
		c := errStr[headEnd]
		if c == '\n' {
			headLines++
			if headLines >= nLines {
				break
			}
		}
	}

	tailStart := len(errStr) - 1
	tailLines := 0
	for ; tailStart > headEnd; tailStart-- {
		c := errStr[tailStart]
		if c == '\n' {
			tailLines++
			if tailLines >= nLines {
				tailStart++
				break
			}
		}
	}

	return errStr[:headEnd] + "\n...\n" + errStr[tailStart:]
}

func installTailCalls(bpfDir string, spec *ebpf.CollectionSpec, coll *ebpf.Collection, load *Program) error {
	// FIXME(JM): This should be replaced by using the cilium/ebpf prog array initialization.

	secToProgName := make(map[string]string)
	for name, prog := range spec.Programs {
		secToProgName[prog.SectionName] = name
	}

	install := func(pinPath string, secPrefix string) error {
		tailCallsMap, err := ebpf.LoadPinnedMap(filepath.Join(bpfDir, pinPath), nil)
		if err != nil {
			return nil
		}
		defer tailCallsMap.Close()

		for i := 0; i < 13; i++ {
			secName := fmt.Sprintf("%s/%d", secPrefix, i)
			if progName, ok := secToProgName[secName]; ok {
				if prog, ok := coll.Programs[progName]; ok {
					err := tailCallsMap.Update(uint32(i), uint32(prog.FD()), ebpf.UpdateAny)
					if err != nil {
						return fmt.Errorf("update of tail-call map '%s' failed: %w", pinPath, err)
					}
				}
			}
		}
		return nil
	}

	if load.TcMap != nil {
		if err := install(load.TcMap.PinPath, load.TcPrefix); err != nil {
			return err
		}
	}

	return nil
}

// MissingConstantsError is returned by [rewriteConstants].
type MissingConstantsError struct {
	// The constants missing from .rodata.
	Constants []string
}

func (m *MissingConstantsError) Error() string {
	return fmt.Sprintf("some constants are missing from .rodata: %s", strings.Join(m.Constants, ", "))
}

func rewriteConstants(spec *ebpf.CollectionSpec, consts map[string]interface{}) error {
	var missing []string

	for n, c := range consts {
		v, ok := spec.Variables[n]
		if !ok {
			missing = append(missing, n)
			continue
		}

		if !v.Constant() {
			return fmt.Errorf("variable %s is not a constant", n)
		}

		if err := v.Set(c); err != nil {
			return fmt.Errorf("rewriting constant %s: %w", n, err)
		}
	}

	if len(missing) != 0 {
		return fmt.Errorf("rewrite constants: %w", &MissingConstantsError{Constants: missing})
	}

	return nil
}

func doLoadProgram(
	bpfDir string,
	load *Program,
	loadOpts *LoadOpts,
	verbose int,
) (*LoadedCollection, error) {

	coll, err := ebpf.LoadCollection(load.Name)
	if err != nil {
		logger.GetLogger().WithError(err).WithField("Error ", err.Error()).Warn(" Failed to load Native Windows Collection ")
		return nil, err
	}
	defer coll.Close()

	collMaps := map[ebpf.MapID]*ebpf.Map{}
	// we need a mapping by ID
	for _, m := range coll.Maps {

		info, err := m.Info()
		if err != nil {
			logger.GetLogger().WithError(err).WithField("map", m.String()).Warn("failed to retrieve BPF map info")
			continue
		}
		id, available := info.ID()
		if !available {
			logger.GetLogger().WithField("map", m.String()).Warn("failed to retrieve BPF map ID, you might be running <4.13")
			continue
		}
		collMaps[id] = m

		if _, exist := load.PinMap[info.Name]; exist {
			pinPath := info.Name
			err = m.Pin(pinPath)
			if err != nil {
				logger.GetLogger().WithField("map", m.String()).Warn("failed to pin map")
			}
		}
	}

	load.LoadedMapsInfo = map[int]bpf.ExtendedMapInfo{}

	var prog *ebpf.Program
	for _, p := range coll.Programs {

		i, err := p.Info()
		if i.Name == load.Label {
			prog = p
		}
		if err != nil {
			logger.GetLogger().WithError(err).WithField("program", p.String()).Warn("failed to retrieve BPF program info, you might be running <4.10")
			break
		}
		ids, available := i.MapIDs()
		if !available {
			logger.GetLogger().WithField("program", p.String()).Warn("failed to retrieve BPF program map IDs, you might be running <4.15")
			break
		}
		for _, id := range ids {
			if _, exist := load.LoadedMapsInfo[int(id)]; exist {
				continue
			}
			xInfo, err := bpf.ExtendedInfoFromMap(collMaps[id])
			if err != nil {
				logger.GetLogger().WithError(err).WithField("mapID", id).Warn("failed to retrieve extended map info")
				break
			}
			load.LoadedMapsInfo[int(id)] = xInfo
		}
	}

	for _, mapLoad := range load.MapLoad {
		pinPath := ""
		if pm, ok := load.PinMap[mapLoad.Name]; ok {
			pinPath = pm.PinPath
		}
		if m, ok := coll.Maps[mapLoad.Name]; ok {
			if err := mapLoad.Load(m, pinPath, mapLoad.Index); err != nil {
				return nil, err
			}
		} else {
			return nil, fmt.Errorf("populating map failed as map '%s' was not found from collection", mapLoad.Name)
		}
	}
	if prog == nil {
		return nil, fmt.Errorf("program for section '%s' not found", load.Label)
	}

	pinPath := load.PinPath
	if _, err := os.Stat(pinPath); err == nil {
		logger.GetLogger().Debugf("Pin file '%s' already exists, repinning", load.PinPath)
		if err := os.Remove(pinPath); err != nil {
			logger.GetLogger().Warnf("Unpinning '%s' failed: %s", pinPath, err)
		}
	}

	// Clone the program so it can be passed on to attach function and unloader after
	// we close the collection.
	prog, err = prog.Clone()
	if err != nil {
		return nil, fmt.Errorf("failed to clone program '%s': %w", load.Label, err)
	}

	if err := prog.Pin(pinPath); err != nil {
		return nil, fmt.Errorf("pinning '%s' to '%s' failed: %w", load.Label, pinPath, err)
	}
	// pin maps

	load.unloader, err = loadOpts.Attach(coll, nil, prog, nil)
	if err != nil {
		if err := prog.Unpin(); err != nil {
			logger.GetLogger().Warnf("Unpinning '%s' failed: %w", pinPath, err)
		}
		return nil, err
	}

	load.Prog = prog

	// in KernelTypes, we use a non-standard BTF which is possibly annotated with symbols
	// from kernel modules. At this point we don't need that anymore, so we can release
	// the memory from it.
	load.KernelTypes = nil

	// Copy the loaded collection before it's destroyed
	if KeepCollection {
		return copyLoadedCollection(coll)
	}
	return nil, nil
}

// The loadProgram loads and attach bpf object @load. It is expected that user
// provides @loadOpts with mandatory attach function and optional open function.
//
// The load process is roughly as follows:
//
//   - load object              | ebpf.LoadCollectionSpec
//   - open callback            | loadOpts.open(spec)
//   - open refferenced maps    |
//   - creates collection       | ebpf.NewCollectionWithOptions(spec, opts)
//   - install tail calls       | loadOpts.ci
//   - load maps with values    |
//   - pin main program         |
//   - attach callback          | loadOpts.attach(coll, spec, prog, progSpec)
//   - print loaded progs/maps  | if KeepCollection == true
//
// The  @loadOpts.open callback can be used to customize ebpf.CollectionSpec
// before it's loaded into kernel (like disable/enable programs).
//
// The @loadOpts.attach callback is used to actually attach main object program
// to desired function/symbol/whatever..
//
// The @loadOpts.ci defines specific installation of tailcalls in object.

func loadProgram(
	bpfDir string,
	load *Program,
	opts *LoadOpts,
	verbose int,
) error {

	// Attach function is mandatory
	if opts.Attach == nil {
		return fmt.Errorf("attach function is not provided")
	}

	lc, err := doLoadProgram(bpfDir, load, opts, verbose)
	if err != nil {
		return err
	}
	if KeepCollection {
		load.LC = filterLoadedCollection(lc)
		printLoadedCollection(load.Name, load.LC)
	}
	return nil
}

func LoadProgram(
	bpfDir string,
	load *Program,
	attach AttachFunc,
	verbose int,
) error {
	return loadProgram(bpfDir, load, &LoadOpts{Attach: attach}, verbose)
}

func LoadProgramOpts(
	bpfDir string,
	load *Program,
	opts *LoadOpts,
	verbose int,
) error {
	return loadProgram(bpfDir, load, opts, verbose)
}
