// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procevents

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/proc"
)

// ToDo: Change these Structure's names to look less obvious
type processBasicInformation32 struct {
	Reserved1       uint32
	PebBaseAddress  uint32
	Reserved2       uint32
	Reserved3       uint32
	UniqueProcessId uint32
	Reserved4       uint32
}

type processBasicInformation64 struct {
	Reserved1       uint64
	PebBaseAddress  uint64
	Reserved2       uint64
	Reserved3       uint64
	UniqueProcessId uint64
	Reserved4       uint64
}

type processEnvironmentBlock32 struct {
	Reserved1         [2]uint8
	BeingDebugged     uint8
	Reserved2         uint8
	Reserved3         [2]uint32
	Ldr               uint32
	ProcessParameters uint32
	// More fields which we don't use so far
}

const (
	ProcessBasicInformation = 0
	ProcessWow64Information = 26
	ProcessQueryInformation = windows.PROCESS_DUP_HANDLE | windows.PROCESS_QUERY_INFORMATION

	SystemExtendedHandleInformationClass = 64
)

var (
	ModuleNt                             = windows.NewLazySystemDLL("ntdll.dll")
	Modkernel32                          = windows.NewLazySystemDLL("kernel32.dll")
	ProcNtQuerySystemInformation         = ModuleNt.NewProc("NtQuerySystemInformation")
	ProcRtlGetNativeSystemInformation    = ModuleNt.NewProc("RtlGetNativeSystemInformation")
	ProcRtlNtStatusToDosError            = ModuleNt.NewProc("RtlNtStatusToDosError")
	ProcNtQueryInformationProcess        = ModuleNt.NewProc("NtQueryInformationProcess")
	ProcNtReadVirtualMemory              = ModuleNt.NewProc("NtReadVirtualMemory")
	ProcNtWow64QueryInformationProcess64 = ModuleNt.NewProc("NtWow64QueryInformationProcess64")
	ProcNtWow64ReadVirtualMemory64       = ModuleNt.NewProc("NtWow64ReadVirtualMemory64")
	procGetNativeSystemInfo              = Modkernel32.NewProc("GetNativeSystemInfo")
	procQueryFullProcessImageNameW       = Modkernel32.NewProc("QueryFullProcessImageNameW")
	procQueryDosDeviceW                  = Modkernel32.NewProc("QueryDosDeviceW")

	processorArchitecture uint
)

type rtlUserProcessParameters32 struct {
	Reserved1                      [16]uint8
	ConsoleHandle                  uint32
	ConsoleFlags                   uint32
	StdInputHandle                 uint32
	StdOutputHandle                uint32
	StdErrorHandle                 uint32
	CurrentDirectoryPathNameLength uint16
	_                              uint16 // Max Length
	CurrentDirectoryPathAddress    uint32
	CurrentDirectoryHandle         uint32
	DllPathNameLength              uint16
	_                              uint16 // Max Length
	DllPathAddress                 uint32
	ImagePathNameLength            uint16
	_                              uint16 // Max Length
	ImagePathAddress               uint32
	CommandLineLength              uint16
	_                              uint16 // Max Length
	CommandLineAddress             uint32
	EnvironmentAddress             uint32
	// More fields which we don't use so far
}

type rtlUserProcessParameters64 struct {
	Reserved1                      [16]uint8
	ConsoleHandle                  uint64
	ConsoleFlags                   uint64
	StdInputHandle                 uint64
	StdOutputHandle                uint64
	StdErrorHandle                 uint64
	CurrentDirectoryPathNameLength uint16
	_                              uint16 // Max Length
	_                              uint32 // Padding
	CurrentDirectoryPathAddress    uint64
	CurrentDirectoryHandle         uint64
	DllPathNameLength              uint16
	_                              uint16 // Max Length
	_                              uint32 // Padding
	DllPathAddress                 uint64
	ImagePathNameLength            uint16
	_                              uint16 // Max Length
	_                              uint32 // Padding
	ImagePathAddress               uint64
	CommandLineLength              uint16
	_                              uint16 // Max Length
	_                              uint32 // Padding
	CommandLineAddress             uint64
	EnvironmentAddress             uint64
	// More fields which we don't use so far
}

type systemInfo struct {
	wProcessorArchitecture      uint16
	wReserved                   uint16
	dwPageSize                  uint32
	lpMinimumApplicationAddress uintptr
	lpMaximumApplicationAddress uintptr
	dwActiveProcessorMask       uintptr
	dwNumberOfProcessors        uint32
	dwProcessorType             uint32
	dwAllocationGranularity     uint32
	wProcessorLevel             uint16
	wProcessorRevision          uint16
}

type processEnvironmentBlock64 struct {
	Reserved1         [2]uint8
	BeingDebugged     uint8
	Reserved2         uint8
	_                 [4]uint8 // padding, since we are 64 bit, the next pointer is 64 bit aligned (when compiling for 32 bit, this is not the case without manual padding)
	Reserved3         [2]uint64
	Ldr               uint64
	ProcessParameters uint64
	// More fields which we don't use so far
}

func convertUTF16ToString(src []byte) string {
	srcLen := len(src) / 2

	codePoints := make([]uint16, srcLen)

	srcIdx := 0
	for i := 0; i < srcLen; i++ {
		codePoints[i] = uint16(src[srcIdx]) | uint16(src[srcIdx+1])<<8
		srcIdx += 2
	}
	return syscall.UTF16ToString(codePoints)
}

func procKernel() procs {
	kernelArgs := []byte("<kernel>\u0000")
	return procs{
		psize:       uint32(processapi.MSG_SIZEOF_EXECVE + len(kernelArgs) + processapi.MSG_SIZEOF_CWD),
		ppid:        kernelPid,
		pnspid:      0,
		pflags:      api.EventProcFS,
		pktime:      1,
		pexe:        kernelArgs,
		size:        uint32(processapi.MSG_SIZEOF_EXECVE + len(kernelArgs) + processapi.MSG_SIZEOF_CWD),
		pid:         kernelPid,
		tid:         kernelPid,
		nspid:       0,
		auid:        proc.InvalidUid,
		flags:       api.EventProcFS,
		ktime:       1,
		exe:         kernelArgs,
		uids:        []uint32{0, 0, 0, 0},
		gids:        []uint32{0, 0, 0, 0},
		effective:   0,
		inheritable: 0,
		permitted:   0,
	}
}

func getCWD(pid uint32) (string, uint32) {
	flags := uint32(0)
	pidstr := fmt.Sprint(pid)

	if pid == 0 {
		return "", flags
	}

	cwd, err := os.Readlink(filepath.Join(option.Config.ProcFS, pidstr, "cwd"))
	if err != nil {
		flags |= api.EventRootCWD | api.EventErrorCWD
		return " ", flags
	}

	if cwd == "/" {
		cwd = " "
		flags |= api.EventRootCWD
	}
	return cwd, flags
}

func updateExecveMapStats(procs int64) {

}

func writeExecveMap(procs []procs) {

}

func getUserProcessParams64(handle windows.Handle) (rtlUserProcessParameters64, error) {
	pebAddress, err := queryPebAddress(syscall.Handle(handle), false)
	if err != nil {
		return rtlUserProcessParameters64{}, fmt.Errorf("cannot locate process PEB: %w", err)
	}

	buf := readProcessMemory(syscall.Handle(handle), false, pebAddress, uint(unsafe.Sizeof(processEnvironmentBlock64{})))
	if len(buf) != int(unsafe.Sizeof(processEnvironmentBlock64{})) {
		return rtlUserProcessParameters64{}, fmt.Errorf("cannot read process PEB")
	}
	peb := (*processEnvironmentBlock64)(unsafe.Pointer(&buf[0]))
	userProcessAddress := peb.ProcessParameters
	buf = readProcessMemory(syscall.Handle(handle), false, userProcessAddress, uint(unsafe.Sizeof(rtlUserProcessParameters64{})))
	if len(buf) != int(unsafe.Sizeof(rtlUserProcessParameters64{})) {
		return rtlUserProcessParameters64{}, fmt.Errorf("cannot read user process parameters")
	}
	return *(*rtlUserProcessParameters64)(unsafe.Pointer(&buf[0])), nil
}

func getProcessTimesFromHandle(hProc windows.Handle) (windows.Rusage, error) {
	var times windows.Rusage

	if err := windows.GetProcessTimes(hProc, &times.CreationTime, &times.ExitTime, &times.KernelTime, &times.UserTime); err != nil {
		return times, err
	}

	return times, nil
}

func queryPebAddress(procHandle syscall.Handle, is32BitProcess bool) (uint64, error) {
	if is32BitProcess {
		//we are on a 64-bit process reading an external 32-bit process
		var wow64 uint

		ret, _, _ := ProcNtQueryInformationProcess.Call(
			uintptr(procHandle),
			uintptr(ProcessWow64Information),
			uintptr(unsafe.Pointer(&wow64)),
			uintptr(unsafe.Sizeof(wow64)),
			uintptr(0),
		)
		if status := windows.NTStatus(ret); status == windows.STATUS_SUCCESS {
			return uint64(wow64), nil
		} else {
			return 0, windows.NTStatus(ret)
		}
	} else {
		//we are on a 64-bit process reading an external 64-bit process
		var info processBasicInformation64

		ret, _, _ := ProcNtQueryInformationProcess.Call(
			uintptr(procHandle),
			uintptr(ProcessBasicInformation),
			uintptr(unsafe.Pointer(&info)),
			uintptr(unsafe.Sizeof(info)),
			uintptr(0),
		)
		if status := windows.NTStatus(ret); status == windows.STATUS_SUCCESS {
			return info.PebBaseAddress, nil
		} else {
			return 0, windows.NTStatus(ret)
		}
	}
}

func readProcessMemory(procHandle syscall.Handle, _ bool, address uint64, size uint) []byte {
	var read uint

	buffer := make([]byte, size)

	ret, _, _ := ProcNtReadVirtualMemory.Call(
		uintptr(procHandle),
		uintptr(address),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&read)),
	)
	if int(ret) >= 0 && read > 0 {
		return buffer[:read]
	}
	return nil
}

var isInit bool = false

func init_once() {
	if isInit {
		return
	}
	var systemInfo systemInfo
	procGetNativeSystemInfo.Call(uintptr(unsafe.Pointer(&systemInfo)))
	processorArchitecture = uint(systemInfo.wProcessorArchitecture)

}

func is32BitProcess(h windows.Handle) bool {
	const (
		PROCESSOR_ARCHITECTURE_INTEL = 0
		PROCESSOR_ARCHITECTURE_ARM   = 5
		PROCESSOR_ARCHITECTURE_ARM64 = 12
		PROCESSOR_ARCHITECTURE_IA64  = 6
		PROCESSOR_ARCHITECTURE_AMD64 = 9
	)
	init_once()
	var procIs32Bits bool
	switch processorArchitecture {
	case PROCESSOR_ARCHITECTURE_INTEL:
		fallthrough
	case PROCESSOR_ARCHITECTURE_ARM:
		procIs32Bits = true
	case PROCESSOR_ARCHITECTURE_ARM64:
		fallthrough
	case PROCESSOR_ARCHITECTURE_IA64:
		fallthrough
	case PROCESSOR_ARCHITECTURE_AMD64:
		var wow64 uint

		ret, _, _ := ProcNtQueryInformationProcess.Call(
			uintptr(h),
			uintptr(ProcessWow64Information),
			uintptr(unsafe.Pointer(&wow64)),
			uintptr(unsafe.Sizeof(wow64)),
			uintptr(0),
		)
		if int(ret) >= 0 {
			if wow64 != 0 {
				procIs32Bits = true
			}
		} else {
			//if the OS does not support the call, we fallback into the bitness of the app
			if unsafe.Sizeof(wow64) == 4 {
				procIs32Bits = true
			}
		}

	default:
		//for other unknown platforms, we rely on process platform
		if unsafe.Sizeof(processorArchitecture) == 8 {
			procIs32Bits = false
		} else {
			procIs32Bits = true
		}
	}
	return procIs32Bits
}

func convertToDrivePath(p string) string {
	rawDrive := strings.Join(strings.Split(p, `\`)[:3], `\`)

	for d := 'A'; d <= 'Z'; d++ {
		szDeviceName := string(d) + ":"
		szTarget := make([]uint16, 512)
		ret, _, _ := procQueryDosDeviceW.Call(uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(szDeviceName))),
			uintptr(unsafe.Pointer(&szTarget[0])),
			uintptr(len(szTarget)))
		if ret != 0 && windows.UTF16ToString(szTarget[:]) == rawDrive {
			return filepath.Join(szDeviceName, p[len(rawDrive):])
		}
	}
	return p
}

func getProcessImagePathFromHandle(hProc windows.Handle) (string, error) {
	buf := make([]uint16, syscall.MAX_LONG_PATH)
	size := uint32(syscall.MAX_LONG_PATH)
	if err := procQueryFullProcessImageNameW.Find(); err == nil { // Vista+
		ret, _, err := procQueryFullProcessImageNameW.Call(
			uintptr(hProc),
			uintptr(0),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)))
		if ret == 0 {
			return "", err
		}
		return windows.UTF16ToString(buf[:]), nil
	}
	return "", fmt.Errorf("Could not find Utilit Method to get image path")
}

func getProcessParams(handle windows.Handle) (rtlUserProcessParameters32, error) {
	pebAddress, err := queryPebAddress(syscall.Handle(handle), true)
	if err != nil {
		return rtlUserProcessParameters32{}, fmt.Errorf("cannot locate process PEB: %w", err)
	}

	buf := readProcessMemory(syscall.Handle(handle), true, pebAddress, uint(unsafe.Sizeof(processEnvironmentBlock32{})))
	if len(buf) != int(unsafe.Sizeof(processEnvironmentBlock32{})) {
		return rtlUserProcessParameters32{}, fmt.Errorf("cannot read process PEB")
	}
	peb := (*processEnvironmentBlock32)(unsafe.Pointer(&buf[0]))
	userProcessAddress := uint64(peb.ProcessParameters)
	buf = readProcessMemory(syscall.Handle(handle), true, userProcessAddress, uint(unsafe.Sizeof(rtlUserProcessParameters32{})))
	if len(buf) != int(unsafe.Sizeof(rtlUserProcessParameters32{})) {
		return rtlUserProcessParameters32{}, fmt.Errorf("cannot read user process parameters")
	}
	return *(*rtlUserProcessParameters32)(unsafe.Pointer(&buf[0])), nil
}

func fetchProcessCmdLineFromHandle(hProc windows.Handle) (string, error) {

	is32Bit := is32BitProcess(hProc)

	if is32Bit {
		procParams32, paramsErr := getProcessParams(hProc)
		if paramsErr != nil {
			return "", paramsErr
		}
		if procParams32.CommandLineLength > 0 {
			commandLine := readProcessMemory(syscall.Handle(hProc), is32Bit, uint64(procParams32.CommandLineAddress), uint(procParams32.CommandLineLength))
			if len(commandLine) != int(procParams32.CommandLineLength) {
				return "", errors.New("cannot read command line")
			}

			return convertUTF16ToString(commandLine), nil
		}
	} else {
		procParams64, paramsErr := getUserProcessParams64(hProc)
		if paramsErr != nil {
			return "", paramsErr
		}
		if procParams64.CommandLineLength > 0 {
			commandLine := readProcessMemory(syscall.Handle(hProc), is32Bit, procParams64.CommandLineAddress, uint(procParams64.CommandLineLength))
			if len(commandLine) != int(procParams64.CommandLineLength) {
				return "", errors.New("cannot read command line")
			}

			return convertUTF16ToString(commandLine), nil
		}
	}

	// If we reach here, we have no command line
	return "", nil
}

func NewProcess(procEntry windows.ProcessEntry32) (procs, error) {
	var empty procs
	var pcmdline string
	var cmdline string
	var ktime uint64
	var pktime uint64
	var pid uint32 = procEntry.ProcessID
	var ppid uint32 = procEntry.ParentProcessID
	var execPath string = windows.UTF16ToString(procEntry.ExeFile[:])
	var pexecPath string
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed Opening Process %d (%s)", pid, execPath)
		return empty, err
	}
	defer windows.CloseHandle(hProc)
	cmdline, err = fetchProcessCmdLineFromHandle(hProc)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Reading process cmdline error")
	}
	times, err := getProcessTimesFromHandle(hProc)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Reading process times error")
	}
	ktime = uint64(times.CreationTime.Nanoseconds())
	// Initialize with invalid uid
	uids := []uint32{proc.InvalidUid, proc.InvalidUid, proc.InvalidUid, proc.InvalidUid}
	gids := []uint32{proc.InvalidUid, proc.InvalidUid, proc.InvalidUid, proc.InvalidUid}
	auid := proc.InvalidUid
	// Get process status
	status, err := proc.GetStatusFromHandle(hProc)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Reading process status error")
	} else {
		uids, err = status.GetUids()
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("Reading Uids of %d failed, falling back to uid: %d", pid, uint32(proc.InvalidUid))
		}

		gids, err = status.GetGids()
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("Reading Uids of %d failed, falling back to gid: %d", pid, uint32(proc.InvalidUid))
		}

		auid, err = status.GetLoginUid()
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("Reading Loginuid of %d failed, falling back to loginuid: %d", pid, uint32(auid))
		}
	}
	// ToDo: In Windows, there is no namespace.
	// The Capabilities are generally privileges which are LUIDs.
	// found using GetTokenInformation with TokenPrivileges, and converted o string using LookupPrivilegeName.
	// They are best expressed as an array of strings, and don't fit in current structure.
	var permitted, effective, inheritable uint64
	var nspid, uts_ns, ipc_ns, mnt_ns, pid_ns, pid_for_children_ns uint32

	var net_ns, time_ns uint32
	var time_for_children_ns uint32

	var cgroup_ns, user_ns uint32
	pcmdline = ""
	pktime = 0
	var pnspid uint32
	if ppid != 0 {
		hPProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(ppid))
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("Failed Opening Parent Process %d", ppid)
		} else {
			defer windows.CloseHandle(hPProc)
			pcmdline, err = fetchProcessCmdLineFromHandle(hPProc)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Reading parent process cmdline error")
			}
			ptimes, err := getProcessTimesFromHandle(hPProc)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Reading parent process times error")
			}
			pktime = uint64(ptimes.CreationTime.Nanoseconds())
			pexecPath, err = getProcessImagePathFromHandle(hPProc)
			if err != nil {
				logger.GetLogger().WithError(err).Warnf("Reading parent process image path error")
			}
		}
	}

	p := procs{
		ppid:                 uint32(ppid),
		pnspid:               pnspid,
		pexe:                 stringToUTF8([]byte(pexecPath)),
		pcmdline:             stringToUTF8([]byte(pcmdline)),
		pflags:               api.EventProcFS | api.EventNeedsCWD | api.EventNeedsAUID,
		pktime:               pktime,
		uids:                 uids,
		gids:                 gids,
		auid:                 auid,
		pid:                  uint32(pid),
		tid:                  uint32(pid), // Read dir does not return threads and we only track tgid
		nspid:                nspid,
		exe:                  stringToUTF8([]byte(execPath)),
		cmdline:              stringToUTF8([]byte(cmdline)),
		flags:                api.EventProcFS | api.EventNeedsCWD | api.EventNeedsAUID,
		ktime:                ktime,
		permitted:            permitted,
		effective:            effective,
		inheritable:          inheritable,
		uts_ns:               uts_ns,
		ipc_ns:               ipc_ns,
		mnt_ns:               mnt_ns,
		pid_ns:               pid_ns,
		pid_for_children_ns:  pid_for_children_ns,
		net_ns:               net_ns,
		time_ns:              time_ns,
		time_for_children_ns: time_for_children_ns,
		cgroup_ns:            cgroup_ns,
		user_ns:              user_ns,
		kernel_thread:        false,
	}

	p.size = uint32(processapi.MSG_SIZEOF_EXECVE + len(p.args()) + processapi.MSG_SIZEOF_CWD)
	p.psize = uint32(processapi.MSG_SIZEOF_EXECVE + len(p.pargs()) + processapi.MSG_SIZEOF_CWD)
	return p, nil

}

func listRunningProcs(procPath string) ([]procs, error) {
	var processes []procs
	snapshotHandle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, uint32(0))
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshotHandle)

	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))
	if err := windows.Process32First(snapshotHandle, &procEntry); err != nil {
		return nil, err
	}

	for {
		p, err := NewProcess(procEntry)
		if err == nil {
			processes = append(processes, p)
		}
		if err = windows.Process32Next(snapshotHandle, &procEntry); err != nil {
			break
		}

	}

	logger.GetLogger().Infof("Read process list appended %d entries", len(processes))
	return processes, nil
}
