#pragma once

// ============================================================================
//  极简 HTTP/1.1 客户端（自包含，无外部依赖）
//
//  设计目标：
//    1. 必须能拿到"原始响应字节"，因为响应验签要覆盖实际收到的 raw body。
//    2. 必须能精确控制请求头顺序与请求体字节，因为请求签名覆盖 raw body。
//    3. 不引入 libcurl，保持零第三方依赖，可直接编入任意工程。
//
//  ---------------------------------------------------------------------------
//  ⚠ 关于 HTTPS（务必阅读）
//
//  本实现默认只支持 http://（明文 TCP）。原因：TLS 需要额外的密码学库，
//  而本模板刻意保持零外部依赖，以便直接编入 Android JNI / 桌面工程。
//
//  生产环境必须使用 HTTPS（见 docs/SECURITY.md）。两种接入方式：
//    A. 若工程已链接 OpenSSL：实现下方 HttpTransport 接口，用 SSL_CTX 包装
//       socket，然后在 CardKeyClient 构造时注入自定义 transport。
//    B. Windows 工程：可改用 WinHTTP（系统自带，支持 TLS）。
//
//  未注入 TLS transport 时访问 https:// 会明确报错，不会静默降级为明文，
//  以免在集成阶段误以为已经加密。
//  ---------------------------------------------------------------------------
// ============================================================================

#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

using socket_t = int;
#define CARDKEY_INVALID_SOCKET (-1)
#define CARDKEY_CLOSE_SOCKET ::close

namespace cardkey {

// ============================================================================
//  URL 解析
// ============================================================================
struct ParsedUrl {
    std::string scheme;  // "http" 或 "https"
    std::string host;
    int port = 80;
    std::string path;  // 以 '/' 开头，含查询串
};

inline ParsedUrl parseUrl(const std::string &url) {
    ParsedUrl parsed;

    const std::size_t schemeEnd = url.find("://");
    if (schemeEnd == std::string::npos) {
        throw std::runtime_error("URL 缺少协议前缀（应为 http:// 或 https://）");
    }

    parsed.scheme = url.substr(0, schemeEnd);
    std::string rest = url.substr(schemeEnd + 3);

    if (parsed.scheme != "http" && parsed.scheme != "https") {
        throw std::runtime_error("不支持的协议：" + parsed.scheme);
    }

    parsed.port = (parsed.scheme == "https") ? 443 : 80;

    const std::size_t pathStart = rest.find('/');
    std::string authority = (pathStart == std::string::npos) ? rest : rest.substr(0, pathStart);
    parsed.path = (pathStart == std::string::npos) ? "/" : rest.substr(pathStart);

    const std::size_t colon = authority.rfind(':');
    if (colon != std::string::npos) {
        parsed.host = authority.substr(0, colon);
        try {
            parsed.port = std::stoi(authority.substr(colon + 1));
        } catch (const std::exception &) {
            throw std::runtime_error("URL 端口号非法");
        }
    } else {
        parsed.host = authority;
    }

    if (parsed.host.empty()) {
        throw std::runtime_error("URL 缺少主机名");
    }

    return parsed;
}

// ============================================================================
//  响应
// ============================================================================
struct HttpResponse {
    int statusCode = 0;
    std::string reason;
    std::map<std::string, std::string> headers;  // 键统一小写
    std::string rawBody;                         // 原始字节，验签必须用它

    std::string header(const std::string &name) const {
        std::string key;
        key.reserve(name.size());
        for (char c : name) {
            key += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        auto it = headers.find(key);
        return it == headers.end() ? std::string() : it->second;
    }
};

// ============================================================================
//  传输层接口 —— 注入 TLS 实现的扩展点
// ============================================================================
class HttpTransport {
public:
    virtual ~HttpTransport() = default;

    /**
     * 发送一次 HTTP 请求并返回原始响应。
     *
     * @param parsed      解析后的 URL
     * @param rawRequest  已完整构造好的 HTTP 请求字节（含请求行、头、体）
     */
    virtual HttpResponse send(const ParsedUrl &parsed, const std::string &rawRequest) = 0;
};

// ============================================================================
//  明文 TCP 传输（内置）
// ============================================================================
class PlainTcpTransport : public HttpTransport {
public:
    explicit PlainTcpTransport(int timeoutSeconds = 10) : m_timeoutSeconds(timeoutSeconds) {}

    HttpResponse send(const ParsedUrl &parsed, const std::string &rawRequest) override {
        if (parsed.scheme == "https") {
            throw std::runtime_error(
                "本模板内置传输只支持 http://。生产环境请注入 TLS transport（见 http_client.h 顶部说明），"
                "不要以明文传输 AppSecret。");
        }

        socket_t sock = CARDKEY_INVALID_SOCKET;
        try {
            sock = connectTo(parsed.host, parsed.port);
            sendAll(sock, rawRequest);
            const std::string raw = receiveAll(sock);
            CARDKEY_CLOSE_SOCKET(sock);
            sock = CARDKEY_INVALID_SOCKET;
            return parseResponse(raw);
        } catch (...) {
            if (sock != CARDKEY_INVALID_SOCKET) {
                CARDKEY_CLOSE_SOCKET(sock);
            }
            throw;
        }
    }

private:
    socket_t connectTo(const std::string &host, int port) {
        struct addrinfo hints;
        std::memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;  // 同时支持 IPv4 / IPv6
        hints.ai_socktype = SOCK_STREAM;

        struct addrinfo *result = nullptr;
        const std::string portText = std::to_string(port);
        if (getaddrinfo(host.c_str(), portText.c_str(), &hints, &result) != 0 || result == nullptr) {
            throw std::runtime_error("域名解析失败：" + host);
        }

        socket_t connected = CARDKEY_INVALID_SOCKET;
        for (struct addrinfo *ai = result; ai != nullptr; ai = ai->ai_next) {
            socket_t candidate = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (candidate == CARDKEY_INVALID_SOCKET) {
                continue;
            }

            if (::connect(candidate, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) == 0) {
                connected = candidate;
                break;
            }

            CARDKEY_CLOSE_SOCKET(candidate);
        }

        freeaddrinfo(result);

        if (connected == CARDKEY_INVALID_SOCKET) {
            throw std::runtime_error("连接服务器失败：" + host + ":" + portText);
        }

        setTimeout(connected, m_timeoutSeconds);
        return connected;
    }

    void setTimeout(socket_t sock, int seconds) {
        struct timeval tv;
        tv.tv_sec = seconds;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    static void sendAll(socket_t sock, const std::string &data) {
        std::size_t sent = 0;
        while (sent < data.size()) {
            const int chunk = static_cast<int>(
                (data.size() - sent) > 65536 ? 65536 : (data.size() - sent));
            const int written = ::send(sock, data.data() + sent, chunk, 0);
            if (written <= 0) {
                throw std::runtime_error("发送请求失败");
            }
            sent += static_cast<std::size_t>(written);
        }
    }

    static std::string receiveAll(socket_t sock) {
        std::string buffer;
        char chunk[8192];

        while (true) {
            const int got = ::recv(sock, chunk, sizeof(chunk), 0);
            if (got == 0) {
                break;  // 对端正常关闭
            }
            if (got < 0) {
                // 超时或出错：若已有数据则返回已收内容，否则视为失败
                if (!buffer.empty()) {
                    break;
                }
                throw std::runtime_error("接收响应失败或超时");
            }
            buffer.append(chunk, static_cast<std::size_t>(got));
        }

        return buffer;
    }

    static HttpResponse parseResponse(const std::string &raw) {
        HttpResponse response;

        const std::size_t headerEnd = raw.find("\r\n\r\n");
        if (headerEnd == std::string::npos) {
            throw std::runtime_error("响应格式非法：缺少头部结束标记");
        }

        const std::string headerBlock = raw.substr(0, headerEnd);
        std::string body = raw.substr(headerEnd + 4);

        // ---- 状态行 ----
        const std::size_t firstLineEnd = headerBlock.find("\r\n");
        const std::string statusLine =
            (firstLineEnd == std::string::npos) ? headerBlock : headerBlock.substr(0, firstLineEnd);

        {
            const std::size_t sp1 = statusLine.find(' ');
            if (sp1 == std::string::npos) {
                throw std::runtime_error("响应状态行非法");
            }
            const std::size_t sp2 = statusLine.find(' ', sp1 + 1);
            const std::string codeText = statusLine.substr(
                sp1 + 1, (sp2 == std::string::npos) ? std::string::npos : sp2 - sp1 - 1);
            try {
                response.statusCode = std::stoi(codeText);
            } catch (const std::exception &) {
                throw std::runtime_error("响应状态码非法");
            }
            if (sp2 != std::string::npos) {
                response.reason = statusLine.substr(sp2 + 1);
            }
        }

        // ---- 头部 ----
        std::size_t cursor = (firstLineEnd == std::string::npos) ? headerBlock.size() : firstLineEnd + 2;
        while (cursor < headerBlock.size()) {
            const std::size_t lineEnd = headerBlock.find("\r\n", cursor);
            const std::string line = headerBlock.substr(
                cursor, (lineEnd == std::string::npos) ? std::string::npos : lineEnd - cursor);

            const std::size_t colon = line.find(':');
            if (colon != std::string::npos) {
                std::string name = line.substr(0, colon);
                std::string value = line.substr(colon + 1);

                // 统一小写键名，便于大小写不敏感查找
                for (char &c : name) {
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                }
                // 去掉值两端空白
                const std::size_t valueStart = value.find_first_not_of(" \t");
                const std::size_t valueEnd = value.find_last_not_of(" \t");
                value = (valueStart == std::string::npos)
                            ? std::string()
                            : value.substr(valueStart, valueEnd - valueStart + 1);

                response.headers[name] = value;
            }

            if (lineEnd == std::string::npos) {
                break;
            }
            cursor = lineEnd + 2;
        }

        // ---- 处理 chunked 传输编码 ----
        const std::string transferEncoding = response.header("Transfer-Encoding");
        if (transferEncoding.find("chunked") != std::string::npos) {
            body = decodeChunked(body);
        } else {
            // 按 Content-Length 截断（服务器可能使用 keep-alive）
            const std::string lengthText = response.header("Content-Length");
            if (!lengthText.empty()) {
                try {
                    const std::size_t declared = static_cast<std::size_t>(std::stoull(lengthText));
                    if (body.size() > declared) {
                        body.resize(declared);
                    }
                } catch (const std::exception &) {
                    // Content-Length 非法时保留已收内容
                }
            }
        }

        response.rawBody = body;
        return response;
    }

    static std::string decodeChunked(const std::string &body) {
        std::string out;
        std::size_t pos = 0;

        while (pos < body.size()) {
            const std::size_t lineEnd = body.find("\r\n", pos);
            if (lineEnd == std::string::npos) {
                break;
            }

            std::string sizeText = body.substr(pos, lineEnd - pos);
            // 去掉 chunk 扩展（如 "1a;ext=val"）
            const std::size_t semicolon = sizeText.find(';');
            if (semicolon != std::string::npos) {
                sizeText = sizeText.substr(0, semicolon);
            }

            std::size_t chunkSize = 0;
            try {
                chunkSize = static_cast<std::size_t>(std::stoull(sizeText, nullptr, 16));
            } catch (const std::exception &) {
                break;
            }

            if (chunkSize == 0) {
                break;
            }

            const std::size_t dataStart = lineEnd + 2;
            if (dataStart + chunkSize > body.size()) {
                out.append(body, dataStart, body.size() - dataStart);
                break;
            }

            out.append(body, dataStart, chunkSize);
            pos = dataStart + chunkSize + 2;  // 跳过数据与结尾 CRLF
        }

        return out;
    }

    int m_timeoutSeconds;
};

// ============================================================================
//  请求构造
// ============================================================================
struct HttpRequest {
    std::string method = "POST";
    std::string url;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;

    void setHeader(const std::string &name, const std::string &value) {
        for (auto &entry : headers) {
            if (entry.first == name) {
                entry.second = value;
                return;
            }
        }
        headers.emplace_back(name, value);
    }

    /**
     * 构造完整请求字节。请求体按原样写入，不做任何重新序列化。
     */
    std::string build(const ParsedUrl &parsed) const {
        std::string out;
        out += method + " " + parsed.path + " HTTP/1.1\r\n";
        out += "Host: " + parsed.host;
        if (!((parsed.scheme == "http" && parsed.port == 80) ||
              (parsed.scheme == "https" && parsed.port == 443))) {
            out += ":" + std::to_string(parsed.port);
        }
        out += "\r\n";

        for (const auto &entry : headers) {
            out += entry.first + ": " + entry.second + "\r\n";
        }

        out += "Content-Length: " + std::to_string(body.size()) + "\r\n";
        out += "Connection: close\r\n";
        out += "\r\n";
        out += body;

        return out;
    }
};

// ============================================================================
//  便捷函数：发一次请求
// ============================================================================
inline HttpResponse httpSend(const HttpRequest &request, HttpTransport *transport = nullptr) {
    const ParsedUrl parsed = parseUrl(request.url);
    const std::string raw = request.build(parsed);

    if (transport != nullptr) {
        return transport->send(parsed, raw);
    }

    PlainTcpTransport defaultTransport;
    return defaultTransport.send(parsed, raw);
}

} // namespace cardkey
