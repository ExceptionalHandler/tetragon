// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v4.23.1
// source: cilium/api/bpf_metadata.proto

package cilium

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type BpfMetadata struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// File system root for bpf. Defaults to "/sys/fs/bpf" if left empty.
	BpfRoot string `protobuf:"bytes,1,opt,name=bpf_root,json=bpfRoot,proto3" json:"bpf_root,omitempty"`
	// 'true' if the filter is on ingress listener, 'false' for egress listener.
	IsIngress bool `protobuf:"varint,2,opt,name=is_ingress,json=isIngress,proto3" json:"is_ingress,omitempty"`
	// Use of the original source address requires kernel datapath support which
	// may or may not be available. 'true' if original source address
	// should be used. Original source address use may still be
	// skipped in scenarios where it is knows to not work.
	UseOriginalSourceAddress bool `protobuf:"varint,3,opt,name=use_original_source_address,json=useOriginalSourceAddress,proto3" json:"use_original_source_address,omitempty"`
	// True if the listener is used for an L7 LB. In this case policy enforcement is done on the
	// destination selected by the listener rather than on the original destination address. For
	// local sources the source endpoint ID is set in socket mark instead of source security ID if
	// 'use_original_source_address' is also true, so that the local source's egress policy is
	// enforced on the bpf datapath.
	// Only valid for egress.
	IsL7Lb bool `protobuf:"varint,4,opt,name=is_l7lb,json=isL7lb,proto3" json:"is_l7lb,omitempty"`
	// Source address to be used whenever the original source address is not used.
	// Either ipv4_source_address or ipv6_source_address depending on the address
	// family of the destination address. If left empty, and no Envoy Cluster Bind
	// Config is provided, the source address will be picked by the local IP stack.
	Ipv4SourceAddress string `protobuf:"bytes,5,opt,name=ipv4_source_address,json=ipv4SourceAddress,proto3" json:"ipv4_source_address,omitempty"`
	Ipv6SourceAddress string `protobuf:"bytes,6,opt,name=ipv6_source_address,json=ipv6SourceAddress,proto3" json:"ipv6_source_address,omitempty"`
	// True if policy should be enforced on l7 LB used. The policy bound to the configured
	// ipv[46]_source_addresses, which must be explicitly set, applies. Ingress policy is
	// enforced on the security identity of the original (e.g., external) source. Egress
	// policy is enforced on the security identity of the backend selected by the load balancer.
	//
	// Deprecation note: This option will be forced 'true' and deprecated when Cilium 1.15 is
	// the oldest supported release.
	EnforcePolicyOnL7Lb bool `protobuf:"varint,7,opt,name=enforce_policy_on_l7lb,json=enforcePolicyOnL7lb,proto3" json:"enforce_policy_on_l7lb,omitempty"`
	// proxy_id is passed to access log messages and allows relating access log messages to
	// listeners.
	ProxyId uint32 `protobuf:"varint,8,opt,name=proxy_id,json=proxyId,proto3" json:"proxy_id,omitempty"`
}

func (x *BpfMetadata) Reset() {
	*x = BpfMetadata{}
	if protoimpl.UnsafeEnabled {
		mi := &file_cilium_api_bpf_metadata_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BpfMetadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BpfMetadata) ProtoMessage() {}

func (x *BpfMetadata) ProtoReflect() protoreflect.Message {
	mi := &file_cilium_api_bpf_metadata_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BpfMetadata.ProtoReflect.Descriptor instead.
func (*BpfMetadata) Descriptor() ([]byte, []int) {
	return file_cilium_api_bpf_metadata_proto_rawDescGZIP(), []int{0}
}

func (x *BpfMetadata) GetBpfRoot() string {
	if x != nil {
		return x.BpfRoot
	}
	return ""
}

func (x *BpfMetadata) GetIsIngress() bool {
	if x != nil {
		return x.IsIngress
	}
	return false
}

func (x *BpfMetadata) GetUseOriginalSourceAddress() bool {
	if x != nil {
		return x.UseOriginalSourceAddress
	}
	return false
}

func (x *BpfMetadata) GetIsL7Lb() bool {
	if x != nil {
		return x.IsL7Lb
	}
	return false
}

func (x *BpfMetadata) GetIpv4SourceAddress() string {
	if x != nil {
		return x.Ipv4SourceAddress
	}
	return ""
}

func (x *BpfMetadata) GetIpv6SourceAddress() string {
	if x != nil {
		return x.Ipv6SourceAddress
	}
	return ""
}

func (x *BpfMetadata) GetEnforcePolicyOnL7Lb() bool {
	if x != nil {
		return x.EnforcePolicyOnL7Lb
	}
	return false
}

func (x *BpfMetadata) GetProxyId() uint32 {
	if x != nil {
		return x.ProxyId
	}
	return 0
}

var File_cilium_api_bpf_metadata_proto protoreflect.FileDescriptor

var file_cilium_api_bpf_metadata_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x63, 0x69, 0x6c, 0x69, 0x75, 0x6d, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x62, 0x70, 0x66,
	0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x06, 0x63, 0x69, 0x6c, 0x69, 0x75, 0x6d, 0x22, 0xcf, 0x02, 0x0a, 0x0b, 0x42, 0x70, 0x66, 0x4d,
	0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x19, 0x0a, 0x08, 0x62, 0x70, 0x66, 0x5f, 0x72,
	0x6f, 0x6f, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x62, 0x70, 0x66, 0x52, 0x6f,
	0x6f, 0x74, 0x12, 0x1d, 0x0a, 0x0a, 0x69, 0x73, 0x5f, 0x69, 0x6e, 0x67, 0x72, 0x65, 0x73, 0x73,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x69, 0x73, 0x49, 0x6e, 0x67, 0x72, 0x65, 0x73,
	0x73, 0x12, 0x3d, 0x0a, 0x1b, 0x75, 0x73, 0x65, 0x5f, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61,
	0x6c, 0x5f, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x18, 0x75, 0x73, 0x65, 0x4f, 0x72, 0x69, 0x67, 0x69,
	0x6e, 0x61, 0x6c, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73,
	0x12, 0x17, 0x0a, 0x07, 0x69, 0x73, 0x5f, 0x6c, 0x37, 0x6c, 0x62, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x06, 0x69, 0x73, 0x4c, 0x37, 0x6c, 0x62, 0x12, 0x2e, 0x0a, 0x13, 0x69, 0x70, 0x76,
	0x34, 0x5f, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x69, 0x70, 0x76, 0x34, 0x53, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x2e, 0x0a, 0x13, 0x69, 0x70, 0x76,
	0x36, 0x5f, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x69, 0x70, 0x76, 0x36, 0x53, 0x6f, 0x75, 0x72,
	0x63, 0x65, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x33, 0x0a, 0x16, 0x65, 0x6e, 0x66,
	0x6f, 0x72, 0x63, 0x65, 0x5f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x5f, 0x6f, 0x6e, 0x5f, 0x6c,
	0x37, 0x6c, 0x62, 0x18, 0x07, 0x20, 0x01, 0x28, 0x08, 0x52, 0x13, 0x65, 0x6e, 0x66, 0x6f, 0x72,
	0x63, 0x65, 0x50, 0x6f, 0x6c, 0x69, 0x63, 0x79, 0x4f, 0x6e, 0x4c, 0x37, 0x6c, 0x62, 0x12, 0x19,
	0x0a, 0x08, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x07, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x49, 0x64, 0x42, 0x2e, 0x5a, 0x2c, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x63, 0x69, 0x6c, 0x69, 0x75, 0x6d, 0x2f, 0x70,
	0x72, 0x6f, 0x78, 0x79, 0x2f, 0x67, 0x6f, 0x2f, 0x63, 0x69, 0x6c, 0x69, 0x75, 0x6d, 0x2f, 0x61,
	0x70, 0x69, 0x3b, 0x63, 0x69, 0x6c, 0x69, 0x75, 0x6d, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_cilium_api_bpf_metadata_proto_rawDescOnce sync.Once
	file_cilium_api_bpf_metadata_proto_rawDescData = file_cilium_api_bpf_metadata_proto_rawDesc
)

func file_cilium_api_bpf_metadata_proto_rawDescGZIP() []byte {
	file_cilium_api_bpf_metadata_proto_rawDescOnce.Do(func() {
		file_cilium_api_bpf_metadata_proto_rawDescData = protoimpl.X.CompressGZIP(file_cilium_api_bpf_metadata_proto_rawDescData)
	})
	return file_cilium_api_bpf_metadata_proto_rawDescData
}

var file_cilium_api_bpf_metadata_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_cilium_api_bpf_metadata_proto_goTypes = []interface{}{
	(*BpfMetadata)(nil), // 0: cilium.BpfMetadata
}
var file_cilium_api_bpf_metadata_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_cilium_api_bpf_metadata_proto_init() }
func file_cilium_api_bpf_metadata_proto_init() {
	if File_cilium_api_bpf_metadata_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_cilium_api_bpf_metadata_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*BpfMetadata); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_cilium_api_bpf_metadata_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_cilium_api_bpf_metadata_proto_goTypes,
		DependencyIndexes: file_cilium_api_bpf_metadata_proto_depIdxs,
		MessageInfos:      file_cilium_api_bpf_metadata_proto_msgTypes,
	}.Build()
	File_cilium_api_bpf_metadata_proto = out.File
	file_cilium_api_bpf_metadata_proto_rawDesc = nil
	file_cilium_api_bpf_metadata_proto_goTypes = nil
	file_cilium_api_bpf_metadata_proto_depIdxs = nil
}
