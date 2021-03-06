// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package verifier

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// VerifierClient is the client API for Verifier service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type VerifierClient interface {
	GetPlatformCert(ctx context.Context, in *GetPlatformCertRequest, opts ...grpc.CallOption) (*GetPlatformCertResponse, error)
	GetEKCert(ctx context.Context, in *GetEKCertRequest, opts ...grpc.CallOption) (*GetEKCertResponse, error)
	GetAK(ctx context.Context, in *GetAKRequest, opts ...grpc.CallOption) (*GetAKResponse, error)
	ActivateCredential(ctx context.Context, in *ActivateCredentialRequest, opts ...grpc.CallOption) (*ActivateCredentialResponse, error)
	Quote(ctx context.Context, in *QuoteRequest, opts ...grpc.CallOption) (*QuoteResponse, error)
	Attest(ctx context.Context, in *AttestRequest, opts ...grpc.CallOption) (*AttestResponse, error)
	PushSecret(ctx context.Context, in *PushSecretRequest, opts ...grpc.CallOption) (*PushSecretResponse, error)
	PullRSAKey(ctx context.Context, in *PullRSAKeyRequest, opts ...grpc.CallOption) (*PullRSAKeyResponse, error)
}

type verifierClient struct {
	cc grpc.ClientConnInterface
}

func NewVerifierClient(cc grpc.ClientConnInterface) VerifierClient {
	return &verifierClient{cc}
}

func (c *verifierClient) GetPlatformCert(ctx context.Context, in *GetPlatformCertRequest, opts ...grpc.CallOption) (*GetPlatformCertResponse, error) {
	out := new(GetPlatformCertResponse)
	err := c.cc.Invoke(ctx, "/verifier.Verifier/GetPlatformCert", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *verifierClient) GetEKCert(ctx context.Context, in *GetEKCertRequest, opts ...grpc.CallOption) (*GetEKCertResponse, error) {
	out := new(GetEKCertResponse)
	err := c.cc.Invoke(ctx, "/verifier.Verifier/GetEKCert", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *verifierClient) GetAK(ctx context.Context, in *GetAKRequest, opts ...grpc.CallOption) (*GetAKResponse, error) {
	out := new(GetAKResponse)
	err := c.cc.Invoke(ctx, "/verifier.Verifier/GetAK", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *verifierClient) ActivateCredential(ctx context.Context, in *ActivateCredentialRequest, opts ...grpc.CallOption) (*ActivateCredentialResponse, error) {
	out := new(ActivateCredentialResponse)
	err := c.cc.Invoke(ctx, "/verifier.Verifier/ActivateCredential", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *verifierClient) Quote(ctx context.Context, in *QuoteRequest, opts ...grpc.CallOption) (*QuoteResponse, error) {
	out := new(QuoteResponse)
	err := c.cc.Invoke(ctx, "/verifier.Verifier/Quote", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *verifierClient) Attest(ctx context.Context, in *AttestRequest, opts ...grpc.CallOption) (*AttestResponse, error) {
	out := new(AttestResponse)
	err := c.cc.Invoke(ctx, "/verifier.Verifier/Attest", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *verifierClient) PushSecret(ctx context.Context, in *PushSecretRequest, opts ...grpc.CallOption) (*PushSecretResponse, error) {
	out := new(PushSecretResponse)
	err := c.cc.Invoke(ctx, "/verifier.Verifier/PushSecret", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *verifierClient) PullRSAKey(ctx context.Context, in *PullRSAKeyRequest, opts ...grpc.CallOption) (*PullRSAKeyResponse, error) {
	out := new(PullRSAKeyResponse)
	err := c.cc.Invoke(ctx, "/verifier.Verifier/PullRSAKey", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// VerifierServer is the server API for Verifier service.
// All implementations should embed UnimplementedVerifierServer
// for forward compatibility
type VerifierServer interface {
	GetPlatformCert(context.Context, *GetPlatformCertRequest) (*GetPlatformCertResponse, error)
	GetEKCert(context.Context, *GetEKCertRequest) (*GetEKCertResponse, error)
	GetAK(context.Context, *GetAKRequest) (*GetAKResponse, error)
	ActivateCredential(context.Context, *ActivateCredentialRequest) (*ActivateCredentialResponse, error)
	Quote(context.Context, *QuoteRequest) (*QuoteResponse, error)
	Attest(context.Context, *AttestRequest) (*AttestResponse, error)
	PushSecret(context.Context, *PushSecretRequest) (*PushSecretResponse, error)
	PullRSAKey(context.Context, *PullRSAKeyRequest) (*PullRSAKeyResponse, error)
}

// UnimplementedVerifierServer should be embedded to have forward compatible implementations.
type UnimplementedVerifierServer struct {
}

func (UnimplementedVerifierServer) GetPlatformCert(context.Context, *GetPlatformCertRequest) (*GetPlatformCertResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetPlatformCert not implemented")
}
func (UnimplementedVerifierServer) GetEKCert(context.Context, *GetEKCertRequest) (*GetEKCertResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetEKCert not implemented")
}
func (UnimplementedVerifierServer) GetAK(context.Context, *GetAKRequest) (*GetAKResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAK not implemented")
}
func (UnimplementedVerifierServer) ActivateCredential(context.Context, *ActivateCredentialRequest) (*ActivateCredentialResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ActivateCredential not implemented")
}
func (UnimplementedVerifierServer) Quote(context.Context, *QuoteRequest) (*QuoteResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Quote not implemented")
}
func (UnimplementedVerifierServer) Attest(context.Context, *AttestRequest) (*AttestResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Attest not implemented")
}
func (UnimplementedVerifierServer) PushSecret(context.Context, *PushSecretRequest) (*PushSecretResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PushSecret not implemented")
}
func (UnimplementedVerifierServer) PullRSAKey(context.Context, *PullRSAKeyRequest) (*PullRSAKeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method PullRSAKey not implemented")
}

// UnsafeVerifierServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to VerifierServer will
// result in compilation errors.
type UnsafeVerifierServer interface {
	mustEmbedUnimplementedVerifierServer()
}

func RegisterVerifierServer(s grpc.ServiceRegistrar, srv VerifierServer) {
	s.RegisterService(&Verifier_ServiceDesc, srv)
}

func _Verifier_GetPlatformCert_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetPlatformCertRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VerifierServer).GetPlatformCert(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/verifier.Verifier/GetPlatformCert",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VerifierServer).GetPlatformCert(ctx, req.(*GetPlatformCertRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Verifier_GetEKCert_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetEKCertRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VerifierServer).GetEKCert(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/verifier.Verifier/GetEKCert",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VerifierServer).GetEKCert(ctx, req.(*GetEKCertRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Verifier_GetAK_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAKRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VerifierServer).GetAK(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/verifier.Verifier/GetAK",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VerifierServer).GetAK(ctx, req.(*GetAKRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Verifier_ActivateCredential_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ActivateCredentialRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VerifierServer).ActivateCredential(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/verifier.Verifier/ActivateCredential",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VerifierServer).ActivateCredential(ctx, req.(*ActivateCredentialRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Verifier_Quote_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(QuoteRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VerifierServer).Quote(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/verifier.Verifier/Quote",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VerifierServer).Quote(ctx, req.(*QuoteRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Verifier_Attest_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AttestRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VerifierServer).Attest(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/verifier.Verifier/Attest",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VerifierServer).Attest(ctx, req.(*AttestRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Verifier_PushSecret_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PushSecretRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VerifierServer).PushSecret(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/verifier.Verifier/PushSecret",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VerifierServer).PushSecret(ctx, req.(*PushSecretRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Verifier_PullRSAKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(PullRSAKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(VerifierServer).PullRSAKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/verifier.Verifier/PullRSAKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(VerifierServer).PullRSAKey(ctx, req.(*PullRSAKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Verifier_ServiceDesc is the grpc.ServiceDesc for Verifier service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Verifier_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "verifier.Verifier",
	HandlerType: (*VerifierServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetPlatformCert",
			Handler:    _Verifier_GetPlatformCert_Handler,
		},
		{
			MethodName: "GetEKCert",
			Handler:    _Verifier_GetEKCert_Handler,
		},
		{
			MethodName: "GetAK",
			Handler:    _Verifier_GetAK_Handler,
		},
		{
			MethodName: "ActivateCredential",
			Handler:    _Verifier_ActivateCredential_Handler,
		},
		{
			MethodName: "Quote",
			Handler:    _Verifier_Quote_Handler,
		},
		{
			MethodName: "Attest",
			Handler:    _Verifier_Attest_Handler,
		},
		{
			MethodName: "PushSecret",
			Handler:    _Verifier_PushSecret_Handler,
		},
		{
			MethodName: "PullRSAKey",
			Handler:    _Verifier_PullRSAKey_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "src/verifier/verifier.proto",
}
