// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package proc

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

// Status reflects fields of `/proc/[pid]/status` and other
// fields that we want
type Status struct {
	// Real, effective, saved, and filesystem.
	Uids []string
	Gids []string

	// /proc/[pid]/loginuid
	LoginUid string
}

type TokenGroups struct {
	GroupCount uint32
	Groups     []syscall.SIDAndAttributes
}

const (
	nanoPerSeconds = 1000000000

	// CLK_TCK is always constant 100 on all architectures except alpha and ia64 which are both
	// obsolete and not supported by Tetragon. Also see
	// https://lore.kernel.org/lkml/agtlq6$iht$1@penguin.transmeta.com/ and
	// https://github.com/containerd/cgroups/pull/12
	clktck = uint64(100)

	InvalidUid = ^uint32(0) // 4294967295 (2^32 - 1)
)

func getIDFromSID(str_sid string) (string, error) {
	tokens := strings.Split(str_sid, "-")
	if len(tokens) <= 1 {
		return "", fmt.Errorf("Could no parse SID %s", str_sid)
	}
	return tokens[len(tokens)-1], nil
}

// fillStatus returns the content of /proc/pid/status as Status
func fillStatus(hProc windows.Handle, status *Status) error {
	var token syscall.Token
	err := syscall.OpenProcessToken(syscall.Handle(hProc), syscall.TOKEN_QUERY, &token)
	if err != nil {
		return err
	}

	defer token.Close()
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	sid_string, err := tokenUser.User.Sid.String()
	if err != nil {
		return err
	}
	str_uid, err := getIDFromSID(sid_string)
	if err != nil {
		return err
	}
	status.Uids = []string{str_uid, str_uid, str_uid, str_uid}
	tokenGroup, err := token.GetTokenPrimaryGroup()
	if err != nil {
		return err
	}
	str_groupid, err := tokenGroup.PrimaryGroup.String()
	if err != nil {
		return err
	}
	str_gid, err := getIDFromSID(str_groupid)
	if err != nil {
		return err
	}
	status.Gids = []string{str_gid, str_gid, str_gid, str_gid}
	return nil
}

func getTokenInfo(t syscall.Token, class uint32, initSize int) (unsafe.Pointer, error) {
	n := uint32(initSize)
	for {
		b := make([]byte, n)
		e := syscall.GetTokenInformation(t, class, &b[0], uint32(len(b)), &n)
		if e == nil {
			return unsafe.Pointer(&b[0]), nil
		}
		if e != syscall.ERROR_INSUFFICIENT_BUFFER {
			return nil, e
		}
		if n <= uint32(len(b)) {
			return nil, e
		}
	}
}

func fillLoginUid(hProc windows.Handle, status *Status) error {

	var token syscall.Token
	err := syscall.OpenProcessToken(syscall.Handle(hProc), syscall.TOKEN_QUERY, &token)
	if err != nil {
		return err
	}
	defer token.Close()

	ret, err := getTokenInfo(token, windows.TokenLogonSid, 32)
	if err != nil {
		return err
	}
	tokenGroups := (*TokenGroups)(ret)
	if tokenGroups.GroupCount == 0 {
		return fmt.Errorf("login uid not found")
	}

	sidAndAttributes := (*syscall.SIDAndAttributes)(unsafe.Pointer(&tokenGroups.Groups[0]))
	logonSid := (*syscall.SID)(unsafe.Pointer(&sidAndAttributes.Sid))
	sid, err := logonSid.String()
	if err != nil {
		return err
	}
	str_sid, err := getIDFromSID(sid)
	if err != nil {
		return err
	}
	status.LoginUid = str_sid
	return nil
}

func GetStatusFromHandle(hProc windows.Handle) (*Status, error) {
	var status Status

	err := fillStatus(hProc, &status)
	if err != nil {
		return nil, err
	}
	// Fill login UID as sid and change below
	status.LoginUid = status.Uids[0]
	fillLoginUid(hProc, &status)
	return &status, nil
}

func GetStatus(pid uint32) (*Status, error) {
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return nil, err
	}
	return GetStatusFromHandle(hProc)
}

func GetProcStatStrings(file string) ([]string, error) {
	return nil, fmt.Errorf(" Not supported on Windows")
}

func GetStatsKtime(s []string) (uint64, error) {
	ktime, err := strconv.ParseUint(s[21], 10, 64)
	if err != nil {
		return 0, err
	}
	return ktime * (nanoPerSeconds / clktck), nil
}

func GetProcPid(pid string) (uint64, error) {
	return strconv.ParseUint(pid, 10, 32)
}

// GetSelfPid() Get current pid
//
// Returns:
//
//	Current pid from procfs and nil on success
//	Zero and error on failure
func GetSelfPid(procfs string) (uint64, error) {
	return uint64(windows.GetCurrentProcessId()), nil
}

// Returns all parsed UIDs on success. If we fail for one value we do not
// return the overflow ID, we return the invalid UID 4294967295
// (-1 as an unsigned integer).
// The overflow ID is returned when the kernel decides and pass it back,
// as it can be a valid indication of UID mapping error.
func (status *Status) GetUids() ([]uint32, error) {
	uids := []uint32{InvalidUid, InvalidUid, InvalidUid, InvalidUid}

	for i, v := range status.Uids {
		uid, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return uids, err
		}
		uids[i] = uint32(uid)
	}

	return uids, nil
}

// Returns all parsed GIDs on success. If we fail for one value we do not
// return the overflow ID, we return the invalid UID 4294967295
// (-1 as an unsigned integer).
// The overflow ID is returned when the kernel decides and pass it back,
// as it can be a valid indication of UID mapping error.
func (status *Status) GetGids() ([]uint32, error) {
	gids := []uint32{InvalidUid, InvalidUid, InvalidUid, InvalidUid}

	for i, v := range status.Gids {
		gid, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return gids, err
		}
		gids[i] = uint32(gid)
	}

	return gids, nil
}

// Returns the task loginuid on success, if we fail we return
// the invalid uid 4294967295 that is same value of tasks
// Returns the task loginuid on success, if we fail we return
// the invalid uid 4294967295 that is same value of tasks
// without loginuid.
func (status *Status) GetLoginUid() (uint32, error) {
	auid, err := strconv.ParseUint(status.LoginUid, 10, 32)
	if err != nil {
		return InvalidUid, err
	}

	return uint32(auid), nil
}

func PrependPath(s string, b []byte) []byte {
	split := strings.Split(string(b), "\u0000")
	split[0] = s
	fullCmd := strings.Join(split[0:], "\u0000")
	return []byte(fullCmd)
}

// LogCurrentLSMContext() Logs the current LSM security context.
func LogCurrentSecurityContext() {
	lsms := map[string]string{
		"selinux":  "",
		"apparmor": "",
		"smack":    "",
	}

	logLSM := false
	for k := range lsms {
		path := ""
		if k == "selinux" {
			path = filepath.Join(option.Config.ProcFS, "/self/attr/current")
		} else {
			path = filepath.Join(option.Config.ProcFS, fmt.Sprintf("/self/attr/%s/current", k))
		}
		data, err := os.ReadFile(path)
		if err == nil && len(data) > 0 {
			lsms[k] = strings.TrimSpace(string(data))
			logLSM = true
		}
	}

	lockdown := ""
	data, err := os.ReadFile("/sys/kernel/security/lockdown")
	if err == nil && len(data) > 0 {
		values := strings.TrimSpace(string(data))
		i := strings.Index(values, "[")
		j := strings.Index(values, "]")
		if i >= 0 && j > i {
			lockdown = values[i+1 : j]
			logLSM = true
		}
		if lockdown == "confidentiality" {
			logger.GetLogger().Warn("Kernel Lockdown is in 'confidentiality' mode, Tetragon will fail to load BPF programs")
		}
	}

	if logLSM {
		/* Now log all LSM security so we can debug later in
		 * case some operations fail.
		 */
		logger.GetLogger().WithFields(logrus.Fields{
			"SELinux":  lsms["selinux"],
			"AppArmor": lsms["apparmor"],
			"Smack":    lsms["smack"],
			"Lockdown": lockdown,
		}).Info("Tetragon current security context")
	}
}
