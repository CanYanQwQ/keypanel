# Windows CNG bridge contract for CardKey API v1

This directory deliberately contains a contract, not a homemade crypto implementation. Build a separately reviewed and signed x64/x86 DLL in an approved native project, then call it from 易语言 using the exact ABI.

## Required primitives

- CNG system RNG for nonce and IV generation.
- HMAC-SHA256 returning 32 bytes, then lowercase hexadecimal in the caller.
- RFC5869 HKDF-SHA256 with IKM/AppSecret, salt/AppID, info `cardkey-enc-v1`, output 32 bytes.
- AES-256-GCM with a 32-byte key, 12-byte IV, UTF-8 AppID AAD, 16-byte tag.
- Constant-time equality for 32-byte signatures.

## ABI rules

- Every buffer is a pointer plus explicit byte length.
- Every output uses caller-owned buffers and reports required size before writing, or returns a clear negative error code.
- Inputs and outputs are binary bytes; Base64 and hexadecimal formatting stay outside the bridge.
- The bridge must never log key material, plaintext card keys, nonce values, IVs, tags or request/response bodies.
- The bridge must zero temporary key/plaintext buffers before returning where the API permits.
- Export undecorated `extern "C"` functions and document x64/x86 calling convention.

Do not load a DLL from the current working directory in production. Resolve a fixed trusted path, verify its Authenticode signature and/or pinned SHA-256, and fail closed when verification fails.

## CNG mapping

Use `bcrypt.dll`:

- `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`.
- `BCryptOpenAlgorithmProvider(BCRYPT_SHA256_ALGORITHM, ...)` and HMAC hash handles for HMAC-SHA256.
- For HKDF, use Windows CNG HKDF support (`BCRYPT_KDF_HKDF`) only on supported target versions and test the exact salt/info properties. Otherwise use an approved RFC5869 implementation inside the bridge, not in 易语言.
- For AES-GCM, configure `BCRYPT_CHAIN_MODE_GCM`, pass a `BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO` with nonce, AAD and tag fields, and verify the tag before releasing plaintext.

## Validation

The following vectors must be checked by the native bridge before it is connected to 易语言:

- Request signature: `42b8ab8d1c81c41609a206fefa6bffcc384fb5480e4f312f18e2401e6f0ca652`.
- Response signature: `e404631865daf3502a1adc751ca7168ad7b0f4f2fad022798f5664bf05a47874`.
- RFC5869 output: `3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865`.
- Card transport vector is documented in the C# and Unity tests; compare Base64 IV/data/tag exactly.

A DLL that only exposes AES-CBC, ECB, unauthenticated encryption, or a “hash string” helper is not sufficient for this protocol.
