#pragma once

// ============================================================================
//  AES-256-GCM（自包含实现，无外部依赖）
//
//  用途：卡密传输加密（客户端 -> 服务端），对应服务端
//        app/Support/CardTransportCrypto.php 的 AES-256-GCM 实现。
//
//  安全说明：
//    - GCM 是认证加密，解密时必须校验 16 字节 tag；校验失败一律拒绝数据。
//    - IV 必须每次随机生成（12 字节），禁止在同一密钥下复用 IV。
//    - AAD 固定为 AppID，把密文绑定到具体应用，防止跨应用重放。
//
//  本文件仅实现 GCM 所需的 AES 分组加密 + GHASH，不实现 CBC/ECB 等其他模式。
// ============================================================================

#include "卡密/基础算法.h"

#include <cstring>
#include <stdexcept>
#include <string>

namespace cardkey {
namespace crypto {

class Aes256Gcm {
public:
    static constexpr std::size_t IvLength = 12;
    static constexpr std::size_t TagLength = 16;
    static constexpr std::size_t KeyLength = 32;

    explicit Aes256Gcm(const Bytes &key) {
        if (key.size() != KeyLength) {
            throw std::runtime_error("AES-256 密钥长度必须为 32 字节");
        }
        expandKey(key);
        initHashSubkey();  // H = AES_K(0^128)，必须先完成密钥扩展
    }

    /**
     * 加密。返回密文（与明文等长）并通过 outTag 返回 16 字节认证标签。
     */
    Bytes encrypt(const Bytes &iv, const Bytes &plaintext, const Bytes &aad, Bytes &outTag) const {
        if (iv.size() != IvLength) {
            throw std::runtime_error("GCM IV 长度必须为 12 字节");
        }

        const Bytes j0 = computeJ0(iv);
        Bytes counter = j0;

        Bytes ciphertext = ctrCrypt(plaintext, counter);
        outTag = computeTag(aad, ciphertext, j0);

        return ciphertext;
    }

    /**
     * 解密并校验认证标签。校验失败抛异常，绝不返回明文。
     */
    Bytes decrypt(const Bytes &iv, const Bytes &ciphertext, const Bytes &tag, const Bytes &aad) const {
        if (iv.size() != IvLength) {
            throw std::runtime_error("GCM IV 长度必须为 12 字节");
        }
        if (tag.size() != TagLength) {
            throw std::runtime_error("GCM 认证标签长度必须为 16 字节");
        }

        const Bytes j0 = computeJ0(iv);
        const Bytes expected = computeTag(aad, ciphertext, j0);

        if (!constantTimeEquals(std::string(expected.begin(), expected.end()),
                                std::string(tag.begin(), tag.end()))) {
            throw std::runtime_error("卡密解密失败：认证标签校验不通过");
        }

        Bytes counter = j0;
        return ctrCrypt(ciphertext, counter);
    }

private:
    // ---- AES-256 密钥扩展：44 个 32 位轮密钥 ----
    void expandKey(const Bytes &key) {
        static const std::uint8_t sbox[256] = {
            0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
        };

        static const std::uint8_t rcon[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

        const std::size_t nk = 8;   // AES-256: 8 个 32 位字
        const std::size_t nr = 14;  // 14 轮

        for (std::size_t i = 0; i < nk; ++i) {
            m_roundKeys[i] = (static_cast<std::uint32_t>(key[i * 4 + 0]) << 24) |
                             (static_cast<std::uint32_t>(key[i * 4 + 1]) << 16) |
                             (static_cast<std::uint32_t>(key[i * 4 + 2]) << 8) |
                             static_cast<std::uint32_t>(key[i * 4 + 3]);
        }

        for (std::size_t i = nk; i < 4 * (nr + 1); ++i) {
            std::uint32_t temp = m_roundKeys[i - 1];

            if (i % nk == 0) {
                temp = (temp << 8) | (temp >> 24);  // RotWord
                temp = (static_cast<std::uint32_t>(sbox[(temp >> 24) & 0xffu]) << 24) |
                       (static_cast<std::uint32_t>(sbox[(temp >> 16) & 0xffu]) << 16) |
                       (static_cast<std::uint32_t>(sbox[(temp >> 8) & 0xffu]) << 8) |
                       static_cast<std::uint32_t>(sbox[temp & 0xffu]);
                temp ^= static_cast<std::uint32_t>(rcon[i / nk]) << 24;
            } else if (i % nk == 4) {
                temp = (static_cast<std::uint32_t>(sbox[(temp >> 24) & 0xffu]) << 24) |
                       (static_cast<std::uint32_t>(sbox[(temp >> 16) & 0xffu]) << 16) |
                       (static_cast<std::uint32_t>(sbox[(temp >> 8) & 0xffu]) << 8) |
                       static_cast<std::uint32_t>(sbox[temp & 0xffu]);
            }

            m_roundKeys[i] = m_roundKeys[i - nk] ^ temp;
        }
    }

    static std::uint32_t subWord(std::uint32_t w) {
        static const std::uint8_t sbox[256] = {
            0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
        };
        return (static_cast<std::uint32_t>(sbox[(w >> 24) & 0xffu]) << 24) |
               (static_cast<std::uint32_t>(sbox[(w >> 16) & 0xffu]) << 16) |
               (static_cast<std::uint32_t>(sbox[(w >> 8) & 0xffu]) << 8) |
               static_cast<std::uint32_t>(sbox[w & 0xffu]);
    }

    // ---- 单块 AES-256 加密 ----
    void encryptBlock(const std::uint8_t in[16], std::uint8_t out[16]) const {
        std::uint32_t s0 = (static_cast<std::uint32_t>(in[0]) << 24) | (static_cast<std::uint32_t>(in[1]) << 16) |
                           (static_cast<std::uint32_t>(in[2]) << 8) | static_cast<std::uint32_t>(in[3]);
        std::uint32_t s1 = (static_cast<std::uint32_t>(in[4]) << 24) | (static_cast<std::uint32_t>(in[5]) << 16) |
                           (static_cast<std::uint32_t>(in[6]) << 8) | static_cast<std::uint32_t>(in[7]);
        std::uint32_t s2 = (static_cast<std::uint32_t>(in[8]) << 24) | (static_cast<std::uint32_t>(in[9]) << 16) |
                           (static_cast<std::uint32_t>(in[10]) << 8) | static_cast<std::uint32_t>(in[11]);
        std::uint32_t s3 = (static_cast<std::uint32_t>(in[12]) << 24) | (static_cast<std::uint32_t>(in[13]) << 16) |
                           (static_cast<std::uint32_t>(in[14]) << 8) | static_cast<std::uint32_t>(in[15]);

        addRoundKey(s0, s1, s2, s3, 0);

        for (std::size_t round = 1; round < 14; ++round) {
            subBytes(s0, s1, s2, s3);
            shiftRows(s0, s1, s2, s3);
            mixColumns(s0, s1, s2, s3);
            addRoundKey(s0, s1, s2, s3, round);
        }

        subBytes(s0, s1, s2, s3);
        shiftRows(s0, s1, s2, s3);
        addRoundKey(s0, s1, s2, s3, 14);

        out[0] = static_cast<std::uint8_t>(s0 >> 24); out[1] = static_cast<std::uint8_t>(s0 >> 16);
        out[2] = static_cast<std::uint8_t>(s0 >> 8);  out[3] = static_cast<std::uint8_t>(s0);
        out[4] = static_cast<std::uint8_t>(s1 >> 24); out[5] = static_cast<std::uint8_t>(s1 >> 16);
        out[6] = static_cast<std::uint8_t>(s1 >> 8);  out[7] = static_cast<std::uint8_t>(s1);
        out[8] = static_cast<std::uint8_t>(s2 >> 24); out[9] = static_cast<std::uint8_t>(s2 >> 16);
        out[10] = static_cast<std::uint8_t>(s2 >> 8); out[11] = static_cast<std::uint8_t>(s2);
        out[12] = static_cast<std::uint8_t>(s3 >> 24); out[13] = static_cast<std::uint8_t>(s3 >> 16);
        out[14] = static_cast<std::uint8_t>(s3 >> 8);  out[15] = static_cast<std::uint8_t>(s3);
    }

    void addRoundKey(std::uint32_t &s0, std::uint32_t &s1, std::uint32_t &s2, std::uint32_t &s3,
                     std::size_t round) const {
        s0 ^= m_roundKeys[round * 4 + 0];
        s1 ^= m_roundKeys[round * 4 + 1];
        s2 ^= m_roundKeys[round * 4 + 2];
        s3 ^= m_roundKeys[round * 4 + 3];
    }

    static void subBytes(std::uint32_t &s0, std::uint32_t &s1, std::uint32_t &s2, std::uint32_t &s3) {
        s0 = subWord(s0);
        s1 = subWord(s1);
        s2 = subWord(s2);
        s3 = subWord(s3);
    }

    // ---- ShiftRows：状态按列组织，对每一行做循环左移 ----
    static void shiftRows(std::uint32_t &s0, std::uint32_t &s1, std::uint32_t &s2, std::uint32_t &s3) {
        const std::uint32_t t0 = s0, t1 = s1, t2 = s2, t3 = s3;

        // 第 0 行不动
        s0 = (t0 & 0xff000000u) | (t1 & 0x00ff0000u) | (t2 & 0x0000ff00u) | (t3 & 0x000000ffu);
        // 第 1 行左移 1
        s1 = (t1 & 0xff000000u) | (t2 & 0x00ff0000u) | (t3 & 0x0000ff00u) | (t0 & 0x000000ffu);
        // 第 2 行左移 2
        s2 = (t2 & 0xff000000u) | (t3 & 0x00ff0000u) | (t0 & 0x0000ff00u) | (t1 & 0x000000ffu);
        // 第 3 行左移 3
        s3 = (t3 & 0xff000000u) | (t0 & 0x00ff0000u) | (t1 & 0x0000ff00u) | (t2 & 0x000000ffu);
    }

    static std::uint8_t xtime(std::uint8_t x) {
        return static_cast<std::uint8_t>((x << 1) ^ ((x & 0x80u) ? 0x1bu : 0x00u));
    }

    static void mixColumns(std::uint32_t &s0, std::uint32_t &s1, std::uint32_t &s2, std::uint32_t &s3) {
        mixColumn(s0);
        mixColumn(s1);
        mixColumn(s2);
        mixColumn(s3);
    }

    static void mixColumn(std::uint32_t &word) {
        const std::uint8_t a0 = static_cast<std::uint8_t>(word >> 24);
        const std::uint8_t a1 = static_cast<std::uint8_t>(word >> 16);
        const std::uint8_t a2 = static_cast<std::uint8_t>(word >> 8);
        const std::uint8_t a3 = static_cast<std::uint8_t>(word);

        const std::uint8_t t = static_cast<std::uint8_t>(a0 ^ a1 ^ a2 ^ a3);

        const std::uint8_t b0 = static_cast<std::uint8_t>(a0 ^ t ^ xtime(static_cast<std::uint8_t>(a0 ^ a1)));
        const std::uint8_t b1 = static_cast<std::uint8_t>(a1 ^ t ^ xtime(static_cast<std::uint8_t>(a1 ^ a2)));
        const std::uint8_t b2 = static_cast<std::uint8_t>(a2 ^ t ^ xtime(static_cast<std::uint8_t>(a2 ^ a3)));
        const std::uint8_t b3 = static_cast<std::uint8_t>(a3 ^ t ^ xtime(static_cast<std::uint8_t>(a3 ^ a0)));

        word = (static_cast<std::uint32_t>(b0) << 24) | (static_cast<std::uint32_t>(b1) << 16) |
               (static_cast<std::uint32_t>(b2) << 8) | static_cast<std::uint32_t>(b3);
    }

    // ---- GCM：J0 = IV || 0x00000001 ----
    static Bytes computeJ0(const Bytes &iv) {
        Bytes j0(16, 0);
        std::memcpy(j0.data(), iv.data(), IvLength);
        j0[15] = 0x01;
        return j0;
    }

    // ---- GCTR：以 inc32 递增计数器做 CTR 模式 ----
    Bytes ctrCrypt(const Bytes &input, Bytes counter) const {
        Bytes output(input.size(), 0);

        for (std::size_t offset = 0; offset < input.size(); offset += 16) {
            inc32(counter);

            std::uint8_t keystream[16];
            encryptBlock(counter.data(), keystream);

            const std::size_t take = (input.size() - offset) < 16 ? (input.size() - offset) : 16;
            for (std::size_t i = 0; i < take; ++i) {
                output[offset + i] = static_cast<std::uint8_t>(input[offset + i] ^ keystream[i]);
            }

            std::memset(keystream, 0, sizeof(keystream));
        }

        return output;
    }

    // 计数器只递增最低 32 位（GCM 规范 inc32）
    static void inc32(Bytes &counter) {
        for (int i = 15; i >= 12; --i) {
            counter[i] = static_cast<std::uint8_t>(counter[i] + 1);
            if (counter[i] != 0) {
                break;
            }
        }
    }

    // ---- GHASH ----
    void ghashMultiply(Bytes &x) const {
        // 按位模拟 GF(2^128) 乘法，参考 NIST SP 800-38D
        Bytes z(16, 0);
        Bytes v = m_h;

        for (int i = 0; i < 128; ++i) {
            const int byteIndex = i / 8;
            const int bitIndex = 7 - (i % 8);

            if ((x[byteIndex] >> bitIndex) & 1u) {
                for (int j = 0; j < 16; ++j) {
                    z[j] = static_cast<std::uint8_t>(z[j] ^ v[j]);
                }
            }

            const bool lsb = (v[15] & 1u) != 0;
            for (int j = 15; j > 0; --j) {
                v[j] = static_cast<std::uint8_t>((v[j] >> 1) | ((v[j - 1] & 1u) << 7));
            }
            v[0] = static_cast<std::uint8_t>(v[0] >> 1);

            if (lsb) {
                v[0] = static_cast<std::uint8_t>(v[0] ^ 0xe1u);
            }
        }

        x = z;
    }

    void ghash(const Bytes &aad, const Bytes &ciphertext, Bytes &out) const {
        Bytes y(16, 0);

        // 处理 AAD（补零到 16 字节边界）
        for (std::size_t offset = 0; offset < aad.size(); offset += 16) {
            Bytes block(16, 0);
            const std::size_t take = (aad.size() - offset) < 16 ? (aad.size() - offset) : 16;
            std::memcpy(block.data(), aad.data() + offset, take);
            for (int i = 0; i < 16; ++i) {
                y[i] = static_cast<std::uint8_t>(y[i] ^ block[i]);
            }
            ghashMultiply(y);
        }

        // 处理密文
        for (std::size_t offset = 0; offset < ciphertext.size(); offset += 16) {
            Bytes block(16, 0);
            const std::size_t take = (ciphertext.size() - offset) < 16 ? (ciphertext.size() - offset) : 16;
            std::memcpy(block.data(), ciphertext.data() + offset, take);
            for (int i = 0; i < 16; ++i) {
                y[i] = static_cast<std::uint8_t>(y[i] ^ block[i]);
            }
            ghashMultiply(y);
        }

        // 长度块：[len(AAD) in bits] || [len(C) in bits]，各 64 位大端
        const std::uint64_t aadBits = static_cast<std::uint64_t>(aad.size()) * 8u;
        const std::uint64_t ctBits = static_cast<std::uint64_t>(ciphertext.size()) * 8u;

        Bytes lengthBlock(16, 0);
        for (int i = 0; i < 8; ++i) {
            lengthBlock[i] = static_cast<std::uint8_t>((aadBits >> (56 - 8 * i)) & 0xffu);
            lengthBlock[8 + i] = static_cast<std::uint8_t>((ctBits >> (56 - 8 * i)) & 0xffu);
        }

        for (int i = 0; i < 16; ++i) {
            y[i] = static_cast<std::uint8_t>(y[i] ^ lengthBlock[i]);
        }
        ghashMultiply(y);

        out = y;
    }

    Bytes computeTag(const Bytes &aad, const Bytes &ciphertext, const Bytes &j0) const {
        Bytes s(16, 0);
        ghash(aad, ciphertext, s);

        std::uint8_t ek[16];
        encryptBlock(j0.data(), ek);

        Bytes tag(16, 0);
        for (int i = 0; i < 16; ++i) {
            tag[i] = static_cast<std::uint8_t>(s[i] ^ ek[i]);
        }
        return tag;
    }

    // H = AES_K(0^128)，构造时计算一次
    void initHashSubkey() {
        const std::uint8_t zero[16] = {0};
        std::uint8_t h[16];
        encryptBlock(zero, h);
        m_h.assign(h, h + 16);
    }

private:
    std::uint32_t m_roundKeys[60] = {0};
    Bytes m_h;
};

} // namespace crypto
} // namespace cardkey
