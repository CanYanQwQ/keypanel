#pragma once

// ============================================================================
//  极简 JSON 解析 / 构造（自包含，无外部依赖）
//
//  只覆盖卡密 API 实际用到的 JSON 子集：
//    - 对象、数组、字符串、整数、浮点、布尔、null
//    - UTF-8 字符串与 \uXXXX 转义（含代理对）
//    - 生成时按需转义，输出紧凑 JSON
//
//  设计取舍：
//    模板要能直接塞进游戏/桌面工程，因此不引入 nlohmann/json 这类第三方依赖，
//    保持自包含，避免引入第三方依赖。
//
//  重要约束（协议要求）：
//    请求签名的摘要必须基于"实际发送的字节"。因此构造请求体后要把
//    序列化结果缓存成字符串，签名与发送都使用同一份字节，禁止重新序列化。
// ============================================================================

#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace cardkey {

class Json {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    Json() : m_type(Type::Null) {}
    Json(std::nullptr_t) : m_type(Type::Null) {}
    Json(bool value) : m_type(Type::Bool), m_bool(value) {}
    Json(int value) : m_type(Type::Number), m_number(static_cast<double>(value)), m_isInteger(true), m_int(value) {}
    Json(long long value) : m_type(Type::Number), m_number(static_cast<double>(value)), m_isInteger(true), m_int(value) {}
    Json(double value) : m_type(Type::Number), m_number(value), m_isInteger(false), m_int(0) {}
    Json(const char *value) : m_type(Type::String), m_string(value ? value : "") {}
    Json(const std::string &value) : m_type(Type::String), m_string(value) {}

    static Json array() {
        Json j;
        j.m_type = Type::Array;
        return j;
    }

    static Json object() {
        Json j;
        j.m_type = Type::Object;
        return j;
    }

    // ---- 类型查询 ----
    Type type() const { return m_type; }
    bool isNull() const { return m_type == Type::Null; }
    bool isBool() const { return m_type == Type::Bool; }
    bool isNumber() const { return m_type == Type::Number; }
    bool isString() const { return m_type == Type::String; }
    bool isArray() const { return m_type == Type::Array; }
    bool isObject() const { return m_type == Type::Object; }

    bool isInteger() const { return m_type == Type::Number && m_isInteger; }

    // ---- 读取 ----
    bool asBool(bool fallback = false) const {
        if (m_type == Type::Bool) return m_bool;
        if (m_type == Type::Number) return m_number != 0.0;
        return fallback;
    }

    long long asInt(long long fallback = 0) const {
        if (m_type == Type::Number) {
            return m_isInteger ? m_int : static_cast<long long>(m_number);
        }
        if (m_type == Type::String) {
            try {
                return std::stoll(m_string);
            } catch (...) {
                return fallback;
            }
        }
        return fallback;
    }

    double asDouble(double fallback = 0.0) const {
        if (m_type == Type::Number) return m_number;
        return fallback;
    }

    std::string asString(const std::string &fallback = std::string()) const {
        if (m_type == Type::String) return m_string;
        if (m_type == Type::Number) return formatNumber();
        if (m_type == Type::Bool) return m_bool ? "true" : "false";
        return fallback;
    }

    bool has(const std::string &key) const {
        return m_type == Type::Object && m_object.find(key) != m_object.end();
    }

    // 取对象成员；不存在时返回 Null 值（不会抛异常，方便链式读取）
    const Json &operator[](const std::string &key) const {
        static const Json nullValue;
        if (m_type != Type::Object) return nullValue;
        auto it = m_object.find(key);
        return it == m_object.end() ? nullValue : it->second;
    }

    // 取数组元素
    const Json &at(std::size_t index) const {
        static const Json nullValue;
        if (m_type != Type::Array || index >= m_array.size()) return nullValue;
        return m_array[index];
    }

    std::size_t size() const {
        if (m_type == Type::Array) return m_array.size();
        if (m_type == Type::Object) return m_object.size();
        return 0;
    }

    const std::vector<Json> &items() const { return m_array; }

    // ---- 写入（仅对象/数组） ----
    Json &set(const std::string &key, const Json &value) {
        if (m_type != Type::Object) {
            m_type = Type::Object;
            m_object.clear();
        }
        m_object[key] = value;
        return *this;
    }

    Json &set(const std::string &key, const std::string &value) { return set(key, Json(value)); }
    Json &set(const std::string &key, const char *value) { return set(key, Json(value)); }
    Json &set(const std::string &key, int value) { return set(key, Json(value)); }
    Json &set(const std::string &key, long long value) { return set(key, Json(value)); }
    Json &set(const std::string &key, bool value) { return set(key, Json(value)); }

    Json &push(const Json &value) {
        if (m_type != Type::Array) {
            m_type = Type::Array;
            m_array.clear();
        }
        m_array.push_back(value);
        return *this;
    }

    // ---- 序列化 ----
    std::string dump() const {
        std::string out;
        write(out);
        return out;
    }

    // ---- 解析 ----
    static Json parse(const std::string &text) {
        Parser parser(text);
        Json value = parser.parseValue();
        parser.skipWhitespace();
        if (!parser.atEnd()) {
            throw std::runtime_error("JSON 解析失败：存在多余内容");
        }
        return value;
    }

    // 宽松解析：失败时返回 Null 而不是抛异常
    static Json tryParse(const std::string &text) {
        try {
            return parse(text);
        } catch (...) {
            return Json();
        }
    }

private:
    void write(std::string &out) const {
        switch (m_type) {
            case Type::Null:
                out += "null";
                break;
            case Type::Bool:
                out += m_bool ? "true" : "false";
                break;
            case Type::Number:
                out += formatNumber();
                break;
            case Type::String:
                writeEscaped(out, m_string);
                break;
            case Type::Array: {
                out += '[';
                for (std::size_t i = 0; i < m_array.size(); ++i) {
                    if (i > 0) out += ',';
                    m_array[i].write(out);
                }
                out += ']';
                break;
            }
            case Type::Object: {
                out += '{';
                bool first = true;
                for (const auto &entry : m_object) {
                    if (!first) out += ',';
                    first = false;
                    writeEscaped(out, entry.first);
                    out += ':';
                    entry.second.write(out);
                }
                out += '}';
                break;
            }
        }
    }

    std::string formatNumber() const {
        if (m_isInteger) {
            return std::to_string(m_int);
        }
        std::ostringstream stream;
        stream.precision(17);
        stream << m_number;
        return stream.str();
    }

    static void writeEscaped(std::string &out, const std::string &value) {
        out += '"';
        for (unsigned char c : value) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20) {
                        char buffer[8];
                        std::snprintf(buffer, sizeof(buffer), "\\u%04x", c);
                        out += buffer;
                    } else {
                        // UTF-8 多字节原样输出，与 PHP JSON_UNESCAPED_UNICODE 行为一致
                        out += static_cast<char>(c);
                    }
                    break;
            }
        }
        out += '"';
    }

    // ------------------------------------------------------------------
    //  解析器
    // ------------------------------------------------------------------
    class Parser {
    public:
        explicit Parser(const std::string &text) : m_text(text), m_pos(0) {}

        bool atEnd() const { return m_pos >= m_text.size(); }

        void skipWhitespace() {
            while (m_pos < m_text.size()) {
                const char c = m_text[m_pos];
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    ++m_pos;
                } else {
                    break;
                }
            }
        }

        Json parseValue() {
            skipWhitespace();
            if (atEnd()) {
                throw std::runtime_error("JSON 解析失败：内容为空");
            }

            switch (m_text[m_pos]) {
                case '{': return parseObject();
                case '[': return parseArray();
                case '"': return Json(parseString());
                case 't': expectLiteral("true");  return Json(true);
                case 'f': expectLiteral("false"); return Json(false);
                case 'n': expectLiteral("null");  return Json();
                default:  return parseNumber();
            }
        }

    private:
        void expectLiteral(const char *literal) {
            const std::size_t len = std::char_traits<char>::length(literal);
            if (m_text.compare(m_pos, len, literal) != 0) {
                throw std::runtime_error("JSON 解析失败：非法字面量");
            }
            m_pos += len;
        }

        Json parseObject() {
            ++m_pos;  // '{'
            Json result = Json::object();
            skipWhitespace();

            if (!atEnd() && m_text[m_pos] == '}') {
                ++m_pos;
                return result;
            }

            while (true) {
                skipWhitespace();
                if (atEnd() || m_text[m_pos] != '"') {
                    throw std::runtime_error("JSON 解析失败：对象键必须是字符串");
                }
                const std::string key = parseString();

                skipWhitespace();
                if (atEnd() || m_text[m_pos] != ':') {
                    throw std::runtime_error("JSON 解析失败：对象键后缺少冒号");
                }
                ++m_pos;

                result.set(key, parseValue());

                skipWhitespace();
                if (atEnd()) {
                    throw std::runtime_error("JSON 解析失败：对象未闭合");
                }
                if (m_text[m_pos] == ',') {
                    ++m_pos;
                    continue;
                }
                if (m_text[m_pos] == '}') {
                    ++m_pos;
                    break;
                }
                throw std::runtime_error("JSON 解析失败：对象中出现非法字符");
            }

            return result;
        }

        Json parseArray() {
            ++m_pos;  // '['
            Json result = Json::array();
            skipWhitespace();

            if (!atEnd() && m_text[m_pos] == ']') {
                ++m_pos;
                return result;
            }

            while (true) {
                result.push(parseValue());

                skipWhitespace();
                if (atEnd()) {
                    throw std::runtime_error("JSON 解析失败：数组未闭合");
                }
                if (m_text[m_pos] == ',') {
                    ++m_pos;
                    continue;
                }
                if (m_text[m_pos] == ']') {
                    ++m_pos;
                    break;
                }
                throw std::runtime_error("JSON 解析失败：数组中出现非法字符");
            }

            return result;
        }

        std::string parseString() {
            ++m_pos;  // 开引号
            std::string out;

            while (true) {
                if (atEnd()) {
                    throw std::runtime_error("JSON 解析失败：字符串未闭合");
                }

                const char c = m_text[m_pos++];

                if (c == '"') {
                    break;
                }

                if (c != '\\') {
                    out += c;
                    continue;
                }

                if (atEnd()) {
                    throw std::runtime_error("JSON 解析失败：转义序列不完整");
                }

                const char escape = m_text[m_pos++];
                switch (escape) {
                    case '"':  out += '"';  break;
                    case '\\': out += '\\'; break;
                    case '/':  out += '/';  break;
                    case 'b':  out += '\b'; break;
                    case 'f':  out += '\f'; break;
                    case 'n':  out += '\n'; break;
                    case 'r':  out += '\r'; break;
                    case 't':  out += '\t'; break;
                    case 'u': {
                        const unsigned int code = parseHex4();
                        appendUtf8(out, code);
                        // 代理对：高位 + 低位
                        if (code >= 0xD800 && code <= 0xDBFF && m_pos + 1 < m_text.size() &&
                            m_text[m_pos] == '\\' && m_text[m_pos + 1] == 'u') {
                            m_pos += 2;
                            const unsigned int low = parseHex4();
                            if (low >= 0xDC00 && low <= 0xDFFF) {
                                const unsigned int combined =
                                    0x10000u + ((code - 0xD800u) << 10) + (low - 0xDC00u);
                                appendUtf8(out, combined);
                            } else {
                                appendUtf8(out, low);
                            }
                        }
                        break;
                    }
                    default:
                        throw std::runtime_error("JSON 解析失败：非法转义字符");
                }
            }

            return out;
        }

        unsigned int parseHex4() {
            if (m_pos + 4 > m_text.size()) {
                throw std::runtime_error("JSON 解析失败：\\u 转义不完整");
            }
            unsigned int value = 0;
            for (int i = 0; i < 4; ++i) {
                const char c = m_text[m_pos++];
                value <<= 4;
                if (c >= '0' && c <= '9')      value |= static_cast<unsigned int>(c - '0');
                else if (c >= 'a' && c <= 'f') value |= static_cast<unsigned int>(c - 'a' + 10);
                else if (c >= 'A' && c <= 'F') value |= static_cast<unsigned int>(c - 'A' + 10);
                else throw std::runtime_error("JSON 解析失败：\\u 转义含非法字符");
            }
            return value;
        }

        static void appendUtf8(std::string &out, unsigned int code) {
            if (code <= 0x7Fu) {
                out += static_cast<char>(code);
            } else if (code <= 0x7FFu) {
                out += static_cast<char>(0xC0u | (code >> 6));
                out += static_cast<char>(0x80u | (code & 0x3Fu));
            } else if (code <= 0xFFFFu) {
                out += static_cast<char>(0xE0u | (code >> 12));
                out += static_cast<char>(0x80u | ((code >> 6) & 0x3Fu));
                out += static_cast<char>(0x80u | (code & 0x3Fu));
            } else {
                out += static_cast<char>(0xF0u | (code >> 18));
                out += static_cast<char>(0x80u | ((code >> 12) & 0x3Fu));
                out += static_cast<char>(0x80u | ((code >> 6) & 0x3Fu));
                out += static_cast<char>(0x80u | (code & 0x3Fu));
            }
        }

        Json parseNumber() {
            const std::size_t start = m_pos;

            if (m_pos < m_text.size() && (m_text[m_pos] == '-' || m_text[m_pos] == '+')) {
                ++m_pos;
            }

            bool isFloat = false;
            while (m_pos < m_text.size()) {
                const char c = m_text[m_pos];
                if (c >= '0' && c <= '9') {
                    ++m_pos;
                } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                    isFloat = isFloat || (c == '.' || c == 'e' || c == 'E');
                    ++m_pos;
                } else {
                    break;
                }
            }

            if (m_pos == start) {
                throw std::runtime_error("JSON 解析失败：非法数字");
            }

            const std::string token = m_text.substr(start, m_pos - start);

            try {
                if (!isFloat) {
                    return Json(static_cast<long long>(std::stoll(token)));
                }
                return Json(std::stod(token));
            } catch (const std::exception &) {
                throw std::runtime_error("JSON 解析失败：数字超出范围");
            }
        }

        const std::string &m_text;
        std::size_t m_pos;
    };

    Type m_type = Type::Null;
    bool m_bool = false;
    double m_number = 0.0;
    bool m_isInteger = false;
    long long m_int = 0;
    std::string m_string;
    std::vector<Json> m_array;
    // 使用有序 map 保证序列化时键顺序稳定，便于比对与调试
    std::map<std::string, Json> m_object;
};

} // namespace cardkey
