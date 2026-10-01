#pragma once

// ============================================================================
//  CardKey 客户端模板 —— 基础密码学原语（自包含，无外部依赖）
//
//  包含：SHA-256 / HMAC-SHA256 / HKDF-SHA256 / Hex / Base64 / 安全随机数
//
//  设计说明：
//    本文件不依赖 OpenSSL，可直接编入 Android JNI、Windows、Linux 工程，
//    不依赖外部库，可直接编入任意工程。AES-256-GCM 见同目录 分组加密.h。
//
//  协议参考：
//    app/Support/ApiSigner.php           签名规范
//    app/Support/CardTransportCrypto.php 传输加密规范
//    docs/API.md                         对外接口文档
// ============================================================================

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <stdexcept>
#include <string>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

namespace cardkey {
namespace crypto {

using Bytes = std::vector<std::uint8_t>;

// ============================================================================
//  SHA-256
// ============================================================================
class Sha256 {
public:
    static constexpr std::size_t DigestSize = 32;
    static constexpr std::size_t BlockSize = 64;

    Sha256() { reset(); }

    void reset() {
        m_length = 0;
        m_bufferLen = 0;
        m_state[0] = 0x6a09e667u;
        m_state[1] = 0xbb67ae85u;
        m_state[2] = 0x3c6ef372u;
        m_state[3] = 0xa54ff53au;
        m_state[4] = 0x510e527fu;
        m_state[5] = 0x9b05688cu;
        m_state[6] = 0x1f83d9abu;
        m_state[7] = 0x5be0cd19u;
    }

    void update(const void *data, std::size_t len) {
        const std::uint8_t *p = static_cast<const std::uint8_t *>(data);
        m_length += static_cast<std::uint64_t>(len);

        while (len > 0) {
            const std::size_t take = (BlockSize - m_bufferLen) < len ? (BlockSize - m_bufferLen) : len;
            std::memcpy(m_buffer + m_bufferLen, p, take);
            m_bufferLen += take;
            p += take;
            len -= take;

            if (m_bufferLen == BlockSize) {
                transform(m_buffer);
                m_bufferLen = 0;
            }
        }
    }

    void update(const std::string &s) { update(s.data(), s.size()); }

    void finish(std::uint8_t out[DigestSize]) {
        const std::uint64_t bitLength = m_length * 8u;

        // 填充：0x80，然后补零到 56 mod 64，最后写入 64 位大端比特长度
        const std::uint8_t pad = 0x80;
        update(&pad, 1);

        const std::uint8_t zero = 0x00;
        while (m_bufferLen != 56) {
            update(&zero, 1);
        }

        std::uint8_t lengthBytes[8];
        for (int i = 0; i < 8; ++i) {
            lengthBytes[i] = static_cast<std::uint8_t>((bitLength >> (56 - 8 * i)) & 0xffu);
        }
        update(lengthBytes, 8);

        for (int i = 0; i < 8; ++i) {
            out[i * 4 + 0] = static_cast<std::uint8_t>((m_state[i] >> 24) & 0xffu);
            out[i * 4 + 1] = static_cast<std::uint8_t>((m_state[i] >> 16) & 0xffu);
            out[i * 4 + 2] = static_cast<std::uint8_t>((m_state[i] >> 8) & 0xffu);
            out[i * 4 + 3] = static_cast<std::uint8_t>(m_state[i] & 0xffu);
        }
    }

    Bytes finish() {
        std::uint8_t out[DigestSize];
        finish(out);
        return Bytes(out, out + DigestSize);
    }

    static Bytes hash(const void *data, std::size_t len) {
        Sha256 ctx;
        ctx.update(data, len);
        return ctx.finish();
    }

    static Bytes hash(const std::string &s) { return hash(s.data(), s.size()); }

private:
    static std::uint32_t rotr(std::uint32_t x, int n) {
        return (x >> n) | (x << (32 - n));
    }

    void transform(const std::uint8_t block[BlockSize]) {
        static const std::uint32_t K[64] = {
            0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
            0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
            0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
            0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
            0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
            0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
            0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
            0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
            0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
            0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
            0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
        };

        std::uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<std::uint32_t>(block[i * 4 + 0]) << 24) |
                   (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
                   static_cast<std::uint32_t>(block[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        std::uint32_t a = m_state[0], b = m_state[1], c = m_state[2], d = m_state[3];
        std::uint32_t e = m_state[4], f = m_state[5], g = m_state[6], h = m_state[7];

        for (int i = 0; i < 64; ++i) {
            const std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const std::uint32_t ch = (e & f) ^ (~e & g);
            const std::uint32_t temp1 = h + S1 + ch + K[i] + w[i];
            const std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        m_state[0] += a; m_state[1] += b; m_state[2] += c; m_state[3] += d;
        m_state[4] += e; m_state[5] += f; m_state[6] += g; m_state[7] += h;
    }

    std::uint32_t m_state[8];
    std::uint64_t m_length;
    std::uint8_t m_buffer[BlockSize];
    std::size_t m_bufferLen;
};

// ============================================================================
//  HMAC-SHA256
// ============================================================================
class HmacSha256 {
public:
    static constexpr std::size_t DigestSize = 32;

    explicit HmacSha256(const std::string &key) {
        std::uint8_t k[Sha256::BlockSize];
        std::memset(k, 0, sizeof(k));

        if (key.size() > Sha256::BlockSize) {
            const Bytes digest = Sha256::hash(key);
            std::memcpy(k, digest.data(), digest.size());
        } else {
            std::memcpy(k, key.data(), key.size());
        }

        std::uint8_t ipad[Sha256::BlockSize];
        std::uint8_t opad[Sha256::BlockSize];
        for (std::size_t i = 0; i < Sha256::BlockSize; ++i) {
            ipad[i] = static_cast<std::uint8_t>(k[i] ^ 0x36u);
            opad[i] = static_cast<std::uint8_t>(k[i] ^ 0x5cu);
        }

        m_inner.update(ipad, sizeof(ipad));
        m_outer.update(opad, sizeof(opad));

        std::memset(k, 0, sizeof(k));
        std::memset(ipad, 0, sizeof(ipad));
        std::memset(opad, 0, sizeof(opad));
    }

    void update(const void *data, std::size_t len) { m_inner.update(data, len); }
    void update(const std::string &s) { m_inner.update(s); }

    void finish(std::uint8_t out[DigestSize]) {
        std::uint8_t inner[DigestSize];
        m_inner.finish(inner);
        m_outer.update(inner, sizeof(inner));
        m_outer.finish(out);
        std::memset(inner, 0, sizeof(inner));
    }

    Bytes finish() {
        std::uint8_t out[DigestSize];
        finish(out);
        return Bytes(out, out + DigestSize);
    }

    static Bytes mac(const std::string &key, const void *data, std::size_t len) {
        HmacSha256 ctx(key);
        ctx.update(data, len);
        return ctx.finish();
    }

    static Bytes mac(const std::string &key, const std::string &data) {
        return mac(key, data.data(), data.size());
    }

private:
    Sha256 m_inner;
    Sha256 m_outer;
};

// ============================================================================
//  HKDF-SHA256
//
//  与服务端 hash_hkdf('sha256', $appSecret, 32, 'cardkey-enc-v1', $appId) 等价：
//      IKM  = appSecret
//      salt = appId
//      info = "cardkey-enc-v1"
// ============================================================================
inline Bytes hkdfSha256(const std::string &ikm, const std::string &salt,
                        const std::string &info, std::size_t outLength) {
    const std::size_t hashLen = Sha256::DigestSize;

    if (outLength == 0 || outLength > 255 * hashLen) {
        throw std::runtime_error("HKDF 输出长度非法");
    }

    // ---- Extract ----
    const Bytes prk = HmacSha256::mac(salt, ikm);

    // ---- Expand ----
    Bytes okm;
    okm.reserve(outLength);

    Bytes block;
    std::uint8_t counter = 1;

    while (okm.size() < outLength) {
        HmacSha256 ctx(std::string(reinterpret_cast<const char *>(prk.data()), prk.size()));
        if (!block.empty()) {
            ctx.update(block.data(), block.size());
        }
        ctx.update(info.data(), info.size());
        ctx.update(&counter, 1);
        block = ctx.finish();

        const std::size_t need = outLength - okm.size();
        const std::size_t take = need < block.size() ? need : block.size();
        okm.insert(okm.end(), block.begin(), block.begin() + static_cast<std::ptrdiff_t>(take));

        ++counter;
    }

    return okm;
}

// ============================================================================
//  Hex
// ============================================================================
inline std::string toHex(const std::uint8_t *data, std::size_t len) {
    static const char *digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(digits[(data[i] >> 4) & 0x0fu]);
        out.push_back(digits[data[i] & 0x0fu]);
    }
    return out;
}

inline std::string toHex(const Bytes &data) {
    return toHex(data.data(), data.size());
}

inline int hexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

inline Bytes fromHex(const std::string &hex) {
    Bytes out;
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("十六进制字符串长度必须为偶数");
    }
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = hexNibble(hex[i]);
        const int lo = hexNibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            throw std::runtime_error("十六进制字符串包含非法字符");
        }
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

// ============================================================================
//  Base64（标准字母表 + 填充，与 PHP base64_encode / base64_decode 一致）
// ============================================================================
inline std::string base64Encode(const std::uint8_t *data, std::size_t len) {
    static const char *alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    std::size_t i = 0;
    while (i + 2 < len) {
        const std::uint32_t triple = (static_cast<std::uint32_t>(data[i]) << 16) |
                                     (static_cast<std::uint32_t>(data[i + 1]) << 8) |
                                     static_cast<std::uint32_t>(data[i + 2]);
        out.push_back(alphabet[(triple >> 18) & 0x3fu]);
        out.push_back(alphabet[(triple >> 12) & 0x3fu]);
        out.push_back(alphabet[(triple >> 6) & 0x3fu]);
        out.push_back(alphabet[triple & 0x3fu]);
        i += 3;
    }

    const std::size_t rest = len - i;
    if (rest == 1) {
        const std::uint32_t triple = static_cast<std::uint32_t>(data[i]) << 16;
        out.push_back(alphabet[(triple >> 18) & 0x3fu]);
        out.push_back(alphabet[(triple >> 12) & 0x3fu]);
        out.push_back('=');
        out.push_back('=');
    } else if (rest == 2) {
        const std::uint32_t triple = (static_cast<std::uint32_t>(data[i]) << 16) |
                                     (static_cast<std::uint32_t>(data[i + 1]) << 8);
        out.push_back(alphabet[(triple >> 18) & 0x3fu]);
        out.push_back(alphabet[(triple >> 12) & 0x3fu]);
        out.push_back(alphabet[(triple >> 6) & 0x3fu]);
        out.push_back('=');
    }

    return out;
}

inline std::string base64Encode(const Bytes &data) {
    return base64Encode(data.data(), data.size());
}

inline Bytes base64Decode(const std::string &encoded) {
    auto value = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };

    Bytes out;
    out.reserve((encoded.size() / 4) * 3);

    std::uint32_t buffer = 0;
    int bits = 0;

    for (char c : encoded) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') {
            continue;
        }
        const int v = value(c);
        if (v < 0) {
            throw std::runtime_error("Base64 字符串包含非法字符");
        }
        buffer = (buffer << 6) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((buffer >> bits) & 0xffu));
        }
    }

    return out;
}

// ============================================================================
//  常量时间比较（对应 PHP hash_equals）
// ============================================================================
inline bool constantTimeEquals(const std::string &a, const std::string &b) {
    if (a.size() != b.size()) {
        return false;
    }
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<std::uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

// ============================================================================
//  密码学安全随机数（nonce / IV 生成）
// ============================================================================
inline Bytes randomBytes(std::size_t len) {
    Bytes out(len);

    // Android 读取 /dev/urandom。这是内核 CSPRNG，
    // 与 OpenSSL 的 RAND_bytes 在 Linux/Android 上使用的是同一来源。
    const int fd = ::open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        throw std::runtime_error("随机数生成失败：无法打开 /dev/urandom");
    }

    std::size_t offset = 0;
    while (offset < len) {
        const ssize_t got = ::read(fd, out.data() + offset, len - offset);
        if (got <= 0) {
            ::close(fd);
            throw std::runtime_error("随机数生成失败：读取 /dev/urandom 出错");
        }
        offset += static_cast<std::size_t>(got);
    }

    ::close(fd);
    return out;
}

// ============================================================================
//  时间戳（Unix 秒）
// ============================================================================
inline std::string unixTimestamp() {
    const std::time_t now = std::time(nullptr);
    return std::to_string(static_cast<long long>(now));
}

} // namespace crypto
} // namespace cardkey
