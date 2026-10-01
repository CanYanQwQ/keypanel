#pragma once

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#define CK_API __declspec(dllexport)
#define CK_CALL __cdecl
#else
#define CK_API
#define CK_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Return 0 on success; negative values are bridge-specific errors. */
CK_API int CK_CALL cardkey_random(uint8_t* output, size_t output_length);

/* HMAC-SHA256 output is exactly 32 bytes. */
CK_API int CK_CALL cardkey_hmac_sha256(
    const uint8_t* key, size_t key_length,
    const uint8_t* message, size_t message_length,
    uint8_t output[32]);

/* RFC5869 HKDF-SHA256. output_length must be <= 255 * 32. */
CK_API int CK_CALL cardkey_hkdf_sha256(
    const uint8_t* ikm, size_t ikm_length,
    const uint8_t* salt, size_t salt_length,
    const uint8_t* info, size_t info_length,
    uint8_t* output, size_t output_length);

/* AES-256-GCM. tag is exactly 16 bytes. Plaintext/ciphertext lengths match. */
CK_API int CK_CALL cardkey_aes256_gcm_encrypt(
    const uint8_t key[32], const uint8_t iv[12],
    const uint8_t* aad, size_t aad_length,
    const uint8_t* plaintext, size_t plaintext_length,
    uint8_t* ciphertext, uint8_t tag[16]);

CK_API int CK_CALL cardkey_aes256_gcm_decrypt(
    const uint8_t key[32], const uint8_t iv[12],
    const uint8_t* aad, size_t aad_length,
    const uint8_t* ciphertext, size_t ciphertext_length,
    const uint8_t tag[16], uint8_t* plaintext);

/* Constant-time equality; returns 1 for equal, 0 otherwise. */
CK_API int CK_CALL cardkey_constant_time_equal(
    const uint8_t* left, const uint8_t* right, size_t length);

#ifdef __cplusplus
}
#endif
