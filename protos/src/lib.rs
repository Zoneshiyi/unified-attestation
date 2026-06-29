//! gRPC 协议契约。tonic-build 在编译期生成代码。
//!
//! 三方共享：attester 用 server 实现 AttesterService，verifier 用 server 实现
//! VerifierService，relying-party 同时作为两者的 client。

tonic::include_proto!("unified_attestation");
