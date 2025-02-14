// Code generated by "stringer -type AttachType -trimprefix Attach"; DO NOT EDIT.

package ebpf

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[AttachNone-0]
	_ = x[AttachCGroupInetIngress-0]
	_ = x[AttachCGroupInetEgress-1]
	_ = x[AttachCGroupInetSockCreate-2]
	_ = x[AttachCGroupSockOps-3]
	_ = x[AttachSkSKBStreamParser-4]
	_ = x[AttachSkSKBStreamVerdict-5]
	_ = x[AttachCGroupDevice-6]
	_ = x[AttachSkMsgVerdict-7]
	_ = x[AttachCGroupInet4Bind-8]
	_ = x[AttachCGroupInet6Bind-9]
	_ = x[AttachCGroupInet4Connect-10]
	_ = x[AttachCGroupInet6Connect-11]
	_ = x[AttachCGroupInet4PostBind-12]
	_ = x[AttachCGroupInet6PostBind-13]
	_ = x[AttachCGroupUDP4Sendmsg-14]
	_ = x[AttachCGroupUDP6Sendmsg-15]
	_ = x[AttachLircMode2-16]
	_ = x[AttachFlowDissector-17]
	_ = x[AttachCGroupSysctl-18]
	_ = x[AttachCGroupUDP4Recvmsg-19]
	_ = x[AttachCGroupUDP6Recvmsg-20]
	_ = x[AttachCGroupGetsockopt-21]
	_ = x[AttachCGroupSetsockopt-22]
	_ = x[AttachTraceRawTp-23]
	_ = x[AttachTraceFEntry-24]
	_ = x[AttachTraceFExit-25]
	_ = x[AttachModifyReturn-26]
	_ = x[AttachLSMMac-27]
	_ = x[AttachTraceIter-28]
	_ = x[AttachCgroupInet4GetPeername-29]
	_ = x[AttachCgroupInet6GetPeername-30]
	_ = x[AttachCgroupInet4GetSockname-31]
	_ = x[AttachCgroupInet6GetSockname-32]
	_ = x[AttachXDPDevMap-33]
	_ = x[AttachCgroupInetSockRelease-34]
	_ = x[AttachXDPCPUMap-35]
	_ = x[AttachSkLookup-36]
	_ = x[AttachXDP-37]
	_ = x[AttachSkSKBVerdict-38]
	_ = x[AttachSkReuseportSelect-39]
	_ = x[AttachSkReuseportSelectOrMigrate-40]
	_ = x[AttachPerfEvent-41]
	_ = x[AttachTraceKprobeMulti-42]
	_ = x[AttachLSMCgroup-43]
	_ = x[AttachStructOps-44]
	_ = x[AttachNetfilter-45]
	_ = x[AttachTCXIngress-46]
	_ = x[AttachTCXEgress-47]
	_ = x[AttachTraceUprobeMulti-48]
	_ = x[AttachCgroupUnixConnect-49]
	_ = x[AttachCgroupUnixSendmsg-50]
	_ = x[AttachCgroupUnixRecvmsg-51]
	_ = x[AttachCgroupUnixGetpeername-52]
	_ = x[AttachCgroupUnixGetsockname-53]
	_ = x[AttachNetkitPrimary-54]
	_ = x[AttachNetkitPeer-55]
	_ = x[AttachWindowsXDP-16777217]
	_ = x[AttachWindowsBind-16777218]
	_ = x[AttachWindowsCGroupInet4Connect-16777219]
	_ = x[AttachWindowsCGroupInet6Connect-16777220]
	_ = x[AttachWindowsCgroupInet4RecvAccept-16777221]
	_ = x[AttachWindowsCgroupInet6RecvAccept-16777222]
	_ = x[AttachWindowsCGroupSockOps-16777223]
	_ = x[AttachWindowsSample-16777224]
	_ = x[AttachWindowsXDPTest-16777225]
	_ = x[AttachWindowsNetEvent-16877116]
	_ = x[AttachWindowsProcess-16877215]
}

const (
	_AttachType_name_0 = "NoneCGroupInetEgressCGroupInetSockCreateCGroupSockOpsSkSKBStreamParserSkSKBStreamVerdictCGroupDeviceSkMsgVerdictCGroupInet4BindCGroupInet6BindCGroupInet4ConnectCGroupInet6ConnectCGroupInet4PostBindCGroupInet6PostBindCGroupUDP4SendmsgCGroupUDP6SendmsgLircMode2FlowDissectorCGroupSysctlCGroupUDP4RecvmsgCGroupUDP6RecvmsgCGroupGetsockoptCGroupSetsockoptTraceRawTpTraceFEntryTraceFExitModifyReturnLSMMacTraceIterCgroupInet4GetPeernameCgroupInet6GetPeernameCgroupInet4GetSocknameCgroupInet6GetSocknameXDPDevMapCgroupInetSockReleaseXDPCPUMapSkLookupXDPSkSKBVerdictSkReuseportSelectSkReuseportSelectOrMigratePerfEventTraceKprobeMultiLSMCgroupStructOpsNetfilterTCXIngressTCXEgressTraceUprobeMultiCgroupUnixConnectCgroupUnixSendmsgCgroupUnixRecvmsgCgroupUnixGetpeernameCgroupUnixGetsocknameNetkitPrimaryNetkitPeer"
	_AttachType_name_1 = "WindowsXDPWindowsBindWindowsCGroupInet4ConnectWindowsCGroupInet6ConnectWindowsCgroupInet4RecvAcceptWindowsCgroupInet6RecvAcceptWindowsCGroupSockOpsWindowsSampleWindowsXDPTest"
	_AttachType_name_2 = "WindowsNetEvent"
	_AttachType_name_3 = "WindowsProcess"
)

var (
	_AttachType_index_0 = [...]uint16{0, 4, 20, 40, 53, 70, 88, 100, 112, 127, 142, 160, 178, 197, 216, 233, 250, 259, 272, 284, 301, 318, 334, 350, 360, 371, 381, 393, 399, 408, 430, 452, 474, 496, 505, 526, 535, 543, 546, 558, 575, 601, 610, 626, 635, 644, 653, 663, 672, 688, 705, 722, 739, 760, 781, 794, 804}
	_AttachType_index_1 = [...]uint8{0, 10, 21, 46, 71, 99, 127, 147, 160, 174}
)

func (i AttachType) String() string {
	switch {
	case i <= 55:
		return _AttachType_name_0[_AttachType_index_0[i]:_AttachType_index_0[i+1]]
	case 16777217 <= i && i <= 16777225:
		i -= 16777217
		return _AttachType_name_1[_AttachType_index_1[i]:_AttachType_index_1[i+1]]
	case i == 16877116:
		return _AttachType_name_2
	case i == 16877215:
		return _AttachType_name_3
	default:
		return "AttachType(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
