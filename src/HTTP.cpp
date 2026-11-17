#include "HTTP.h"
#include "WebSocket.h"
#include "TLS.h"
#include "Log.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <limits>
#include <string>
#include <string_view>
#include <exception>

namespace
{
// 去除字符串首尾空白(原地)
void trim(std::string &s)
{
    auto not_space = [](unsigned char c)
    {
        return !std::isspace(c);
    };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
    s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
}

/*
 *@brief RFC 7230 的 token 字符
 *@note  请求方法与头部字段名都必须是 token:出现空格/控制字符/分隔符时,
 *       不同实现(反向代理与本服务器)对同一段字节的解析会不一致,是请求
 *       走私(Smuggling)的经典入口,这里一律拒绝。
 */
bool is_token_char(unsigned char c) noexcept
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
        return true;
    switch (c)
    {
    case '!':
    case '#':
    case '$':
    case '%':
    case '&':
    case '\'':
    case '*':
    case '+':
    case '-':
    case '.':
    case '^':
    case '_':
    case '`':
    case '|':
    case '~':
        return true;
    default:
        return false;
    }
}

bool is_token(const std::string &text) noexcept
{
    if (text.empty())
        return false;
    for (const unsigned char c : text)
    {
        if (!is_token_char(c))
            return false;
    }
    return true;
}

/*
 *@brief 头部值(逗号分隔的 token 列表)中是否含指定 token
 *@param value 头部原始值,例如 "h2c, WebSocket"
 *@param token 目标 token(小写),例如 "websocket"
 *@note  Upgrade / Connection 都是 token 列表,必须按完整 token 比较:
 *       既不能把 "upgrade-x" 当成 "upgrade",也不能漏掉 "h2c, websocket"
 *       这种多协议写法 —— 它直接决定请求进入哪个分发入口
 */
bool has_list_token(const std::string &value, const char *token)
{
    const std::string lowered = HTTP::to_lower(value);
    const std::string needle(token);
    std::size_t pos = 0;
    while (pos <= lowered.size())
    {
        const std::size_t comma = lowered.find(',', pos);
        std::string item = lowered.substr(
                               pos, comma == std::string::npos ? std::string::npos : comma - pos);
        trim(item);
        if (item == needle)
            return true;
        if (comma == std::string::npos)
            break;
        pos = comma + 1;
    }
    return false;
}

/*
 *@brief 严格解析十进制长度(Content-Length)
 *@return false 表示不是"纯十进制数字"或数值溢出
 *@note  std::stoul 会接受 "+5"、"5abc" 这类写法(只解析前缀),
 *        与反向代理的解析结果可能不一致,必须逐字符校验。
 */
bool parse_decimal_size(const std::string &text, size_t &out) noexcept
{
    if (text.empty())
        return false;

    size_t value = 0;
    for (const unsigned char c : text)
    {
        if (c < '0' || c > '9')
            return false;
        const size_t digit = static_cast<size_t>(c - '0');
        if (value > (std::numeric_limits<size_t>::max() - digit) / 10)
            return false; // 溢出
        value = value * 10 + digit;
    }
    out = value;
    return true;
}

/*
 *@brief 严格解析十六进制块长度(chunk-size)
 *@return false 表示含非十六进制字符或数值溢出
 */
bool parse_hex_size(const std::string &text, size_t &out) noexcept
{
    if (text.empty())
        return false;

    size_t value = 0;
    for (const unsigned char c : text)
    {
        size_t digit = 0;
        if (c >= '0' && c <= '9')
            digit = static_cast<size_t>(c - '0');
        else if (c >= 'a' && c <= 'f')
            digit = static_cast<size_t>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            digit = static_cast<size_t>(c - 'A' + 10);
        else
            return false;

        if (value > (std::numeric_limits<size_t>::max() - digit) / 16)
            return false; // 溢出
        value = value * 16 + digit;
    }
    out = value;
    return true;
}

/*
 *@brief 响应头 / 状态短语输出前的清洗(直接追加到目标串)
 *@param out 目标串
 *@param text 原始文本
 *@param keep_tab 是否保留水平制表符(头部值允许 HTAB,字段名不允许)
 *@note  脚本可以把请求参数直接写进响应头(HTTP.send.header / status 的原因短语)。
 *       若不清洗,`%0d%0aX-Evil: 1` 就能拆出额外的响应头甚至响应体(HTTP 响应
 *       拆分),进而造成缓存投毒。这里在"唯一出口"serialize_head 上兜底。
 *       直接 append 而不是返回新字符串:响应序列化每个请求都要走一次,
 *       干净文本不需要任何额外分配。
 */
void append_header_safe(std::string &out, std::string_view text, bool keep_tab)
{
    for (const unsigned char c : text)
    {
        if (c == '\r' || c == '\n')
            continue;
        if (c == '\t' && keep_tab)
        {
            out.push_back('\t');
            continue;
        }
        if (c < 0x20 || c == 0x7F)
        {
            out.push_back(' ');
            continue;
        }
        out.push_back(static_cast<char>(c));
    }
}

/*
 *@brief 解析查询字符串 k1=v1&k2=v2 到 map (已解码)
 */
void parse_query(const std::string &qs,
                 std::map<std::string, std::string> &out)
{
    size_t pos = 0;
    while (pos < qs.size())
    {
        size_t amp = qs.find('&', pos);
        std::string pair = (amp == std::string::npos)
                           ? qs.substr(pos)
                           : qs.substr(pos, amp - pos);
        if (!pair.empty())
        {
            size_t eq = pair.find('=');
            if (eq == std::string::npos)
                out[HTTP::url_decode(pair)] = "";
            else
                out[HTTP::url_decode(pair.substr(0, eq))] =
                    HTTP::url_decode(pair.substr(eq + 1));
        }
        if (amp == std::string::npos)
            break;
        pos = amp + 1;
    }
}

// 解析 Cookie 请求头:name1=value1; name2=value2 ...
// 注意:Cookie 名区分大小写;值按规范原样保留(不做 URL 解码)
void parse_cookies(const std::string &header,
                   std::map<std::string, std::string> &out)
{
    size_t pos = 0;
    while (pos < header.size())
    {
        size_t semi = header.find(';', pos);
        std::string pair = (semi == std::string::npos)
                           ? header.substr(pos)
                           : header.substr(pos, semi - pos);
        trim(pair);
        if (!pair.empty())
        {
            size_t eq = pair.find('=');
            if (eq == std::string::npos)
            {
                out[pair] = "";
            }
            else
            {
                std::string name = HTTP::trim_copy(pair.substr(0, eq));
                std::string value = HTTP::trim_copy(pair.substr(eq + 1));
                // 去除可选的包裹双引号
                if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
                    value = value.substr(1, value.size() - 2);
                if (!name.empty())
                    out[name] = value;
            }
        }
        if (semi == std::string::npos)
            break;
        pos = semi + 1;
    }
}

// 根据请求头读取请求体(支持 Content-Length 与 chunked)
// 返回:0 正常,或应回应的 HTTP 状态码(400/408/413/431)
//
// 调用前 Header_get 已经做过定界校验:
//   - Content-Length 与 Transfer-Encoding 不会同时存在(RFC 7230 要求拒绝);
//   - 两者都不会重复出现;
//   - Transfer-Encoding 的值一定是 chunked(否则解析阶段就拒绝了)。
// 这里只负责真正把字节读出来。
int read_body(TCP::Base_Link &link,
              const std::map<std::string, std::string> &headers,
              std::string &body,
              const std::chrono::steady_clock::time_point &deadline,
              bool infinite,
              const HTTP::Limits &limits)
{
    // 计算到总 deadline 为止的剩余超时:0 = 无限,-1 = 已耗尽
    auto remain = [&]() -> int
    {
        if (infinite)
            return 0;
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            return -1;
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      deadline - now)
                  .count();
        return ms > 0 ? static_cast<int>(ms) : -1;
    };

    auto te = headers.find("transfer-encoding");
    if (te != headers.end())
    {
        // 分块传输编码
        while (true)
        {
            int t = remain();
            if (t < 0)
                return 408;

            std::string line;
            TCP::ReadStatus st = link.Read_until("\r\n", t,
                                                 limits.max_header_line, line);
            if (st == TCP::ReadStatus::Overflow)
                return 400; // 块长度行都不合法,直接当畸形请求处理
            if (st == TCP::ReadStatus::Timeout)
                return 408;
            if (st == TCP::ReadStatus::Closed)
                return 400;

            size_t semi = line.find(';');
            std::string size_str = (semi == std::string::npos)
                                   ? line
                                   : line.substr(0, semi);
            trim(size_str);

            size_t chunk_size = 0;
            if (!parse_hex_size(size_str, chunk_size))
                return 400; // 只接受纯十六进制数字

            if (chunk_size == 0)
            {
                /*
                 * 最后一块之后是"trailer 段 + 空行"。
                 * 旧实现只吃掉一行,带 trailer 的请求会把剩下的 trailer 头
                 * 留在连接里,被当成下一个请求解析(请求走私 / 连接错位);
                 * 这里必须一直读到空行。
                 */
                for (size_t i = 0;; ++i)
                {
                    if (limits.max_header_count != 0 && i >= limits.max_header_count)
                        return 431;
                    int t2 = remain();
                    if (t2 < 0)
                        return 408;
                    std::string trailer;
                    TCP::ReadStatus tst = link.Read_until("\r\n", t2,
                                                          limits.max_header_line, trailer);
                    if (tst == TCP::ReadStatus::Overflow)
                        return 431;
                    if (tst == TCP::ReadStatus::Timeout)
                        return 408;
                    if (tst != TCP::ReadStatus::Ok)
                        return 400;
                    if (trailer.empty())
                        break; // 空行 = 报文结束
                }
                break;
            }

            // 先减后比,避免 body.size() + chunk_size 溢出
            if (body.size() > limits.max_body_bytes ||
                    chunk_size > limits.max_body_bytes - body.size())
                return 413;

            size_t got = 0;
            while (got < chunk_size)
            {
                int t3 = remain();
                if (t3 < 0)
                    return 408;
                std::string chunk = link.Receive_str(chunk_size - got, t3);
                if (chunk.empty())
                    return 408; // 超时或连接关闭
                body += chunk;
                got += chunk.size();
            }

            // 块尾 CRLF:数据之后必须紧跟 CRLF,中间不允许有别的内容
            int t4 = remain();
            if (t4 < 0)
                return 408;
            std::string crlf;
            TCP::ReadStatus cst = link.Read_until("\r\n", t4,
                                                  limits.max_header_line, crlf);
            if (cst == TCP::ReadStatus::Timeout)
                return 408;
            if (cst != TCP::ReadStatus::Ok || !crlf.empty())
                return 400;
        }
        return 0;
    }

    auto cl = headers.find("content-length");
    if (cl != headers.end())
    {
        size_t want = 0;
        if (!parse_decimal_size(cl->second, want))
            return 400; // 只接受纯十进制数字(拒绝 "+5" / "5abc" / "-1")
        if (want > limits.max_body_bytes)
            return 413;

        body.reserve(want);
        while (body.size() < want)
        {
            int t = remain();
            if (t < 0)
                return 408;
            std::string chunk = link.Receive_str(want - body.size(), t);
            if (chunk.empty())
                return 408; // 超时或连接关闭
            body += chunk;
        }
    }
    return 0;
}

// 将 WebSocket 回调(std::function)适配为 Router,
// 使其能被统一注册进路由映射表并参与路径匹配
class WsRouter : public HTTP::Router
{
public:
    explicit WsRouter(HTTP::Distributor::WsHandler handler)
        : handler_(std::move(handler)) {}

    bool supports(HTTP::RequestType type) const override
    {
        return type == HTTP::RequestType::WebSocket;
    }

    void handle_websocket(HTTP::WebSocket &ws, const HTTP::Header_get &header) override
    {
        if (handler_)
            handler_(ws, header);
    }

private:
    HTTP::Distributor::WsHandler handler_;
};

// ==================== 访问日志辅助 ====================

// 访问日志总开关(默认开启);连接/请求/响应/WebSocket 日志共用
std::atomic<bool> g_access_log{true};

bool access_log_on() noexcept
{
    return g_access_log.load(std::memory_order_relaxed);
}

// 协议名:便于在日志中区分明文连接与 TLS 连接(带实际协商版本,如 "TLS 1.3")
std::string protocol_name(const TCP::Base_Link &link)
{
    if (!link.is_tls())
        return "TCP";
    const std::string version = link.tls_protocol();
    return version.empty() ? std::string("TLS") : version;
}

// 请求类型名
const char *request_type_name(HTTP::RequestType type) noexcept
{
    switch (type)
    {
    case HTTP::RequestType::WebSocket:
        return "WebSocket";
    case HTTP::RequestType::Custom:
        return "Custom";
    case HTTP::RequestType::Http:
    default:
        return "Http";
    }
}

// 按状态码分档选择日志颜色
Log::Color status_color(int status) noexcept
{
    if (status >= 500)
        return Log::Color::Red;
    if (status >= 400)
        return Log::Color::Yellow;
    if (status >= 300)
        return Log::Color::LightCyan;
    if (status >= 200)
        return Log::Color::LightGreen;
    return Log::Color::LightGray;
}

// 原因短语:优先使用自定义值,否则按状态码生成
std::string response_reason(const HTTP::Header_send &res)
{
    return res.status_text.empty() ? HTTP::status_text(res.status) : res.status_text;
}

/*
 *@brief 拼一条响应日志的开头:"<label><status> <reason>"
 *@note  原因短语可能来自脚本(HTTP.send.status(code, text)),要清洗后再进日志;
 *       这里直接追加到目标串,干净文本不做额外拷贝(每请求都会走一次)
 */
std::string response_log_head(const HTTP::Header_send &res, const char *label)
{
    std::string out(label);
    out += std::to_string(res.status);
    out += ' ';
    Log::append_sanitized(out, response_reason(res));
    return out;
}

// 把一段耗时格式化为 "1.234 s"，便于日志阅读
std::string format_duration(std::chrono::steady_clock::duration d)
{
    const long long ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(d).count();
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.3f s", static_cast<double>(ms) / 1000.0);
    return std::string(buf);
}

// 将过滤器函数(lambda)适配为 RequestFilter,便于统一注册与执行
class FuncFilter : public HTTP::RequestFilter
{
public:
    explicit FuncFilter(HTTP::Distributor::FilterFunc func)
        : func_(std::move(func)) {}

    HTTP::FilterAction inspect(HTTP::Header_get &request, TCP::Base_Link &link,
                               HTTP::Header_send &response) override
    {
        return func_ ? func_(request, link, response) : HTTP::FilterAction::Continue;
    }

private:
    HTTP::Distributor::FilterFunc func_;
};

// 当前请求上下文的作用域守卫:处理期间设置,离开作用域自动清除,
// 避免线程复用时残留已销毁的请求指针
class RequestScope
{
public:
    explicit RequestScope(const HTTP::Header_get *request)
    {
        HTTP::detail::set_current_request(request);
    }
    ~RequestScope()
    {
        HTTP::detail::set_current_request(nullptr);
    }
    RequestScope(const RequestScope &) = delete;
    RequestScope &operator=(const RequestScope &) = delete;
};
} // anonymous namespace

namespace HTTP
{
// ==================== 当前请求上下文 ====================

namespace detail
{
namespace
{
// 工作线程与连接一一对应,故用 thread_local 保存即可;
// Distributor 在调用处理器前后设置/清除,避免指针悬垂
thread_local const Header_get *t_current_request = nullptr;
thread_local bool t_reuse_allowed = true;
} // namespace

const Header_get *current_request() noexcept
{
    return t_current_request;
}

void set_current_request(const Header_get *request) noexcept
{
    t_current_request = request;
}

bool reuse_allowed() noexcept
{
    return t_reuse_allowed;
}

void set_reuse_allowed(bool enable) noexcept
{
    t_reuse_allowed = enable;
}
} // namespace detail

// ==================== 访问日志 ====================

bool access_log_enabled() noexcept
{
    return access_log_on();
}

void set_access_log(bool enable)
{
    g_access_log.store(enable, std::memory_order_relaxed);
}

// ==================== 工具函数 ====================

std::string to_lower(std::string str)
{
    std::transform(str.begin(), str.end(), str.begin(),
                   [](unsigned char c)
    {
        return static_cast<char>(std::tolower(c));
    });
    return str;
}

std::string trim_copy(std::string str)
{
    trim(str);
    return str;
}

std::string url_decode(const std::string &str)
{
    auto hex_val = [](char c) -> int
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        return -1;
    };

    std::string decoded;
    decoded.reserve(str.size());
    for (size_t i = 0; i < str.size(); ++i)
    {
        if (str[i] == '%' && i + 2 < str.size())
        {
            int high = hex_val(str[i + 1]);
            int low = hex_val(str[i + 2]);
            if (high != -1 && low != -1)
            {
                decoded.push_back(static_cast<char>((high << 4) | low));
                i += 2;
                continue;
            }
            decoded.push_back(str[i]);
        }
        else if (str[i] == '+')
        {
            decoded.push_back(' ');
        }
        else
        {
            decoded.push_back(str[i]);
        }
    }
    return decoded;
}

std::string url_encode(const std::string &str)
{
    static const char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(str.size());
    for (unsigned char c : str)
    {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            out.push_back(static_cast<char>(c));
        else if (c == ' ')
            out.push_back('+');
        else
        {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0x0F]);
        }
    }
    return out;
}

std::string base64_encode(const unsigned char *data, size_t len)
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    size_t i = 0;
    for (; i + 2 < len; i += 3)
    {
        uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
                     (static_cast<uint32_t>(data[i + 1]) << 8) |
                     static_cast<uint32_t>(data[i + 2]);
        out.push_back(tbl[(n >> 18) & 63]);
        out.push_back(tbl[(n >> 12) & 63]);
        out.push_back(tbl[(n >> 6) & 63]);
        out.push_back(tbl[n & 63]);
    }
    if (i < len)
    {
        bool two = (i + 1 < len);
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (two)
            n |= static_cast<uint32_t>(data[i + 1]) << 8;
        out.push_back(tbl[(n >> 18) & 63]);
        out.push_back(tbl[(n >> 12) & 63]);
        out.push_back(two ? tbl[(n >> 6) & 63] : '=');
        out.push_back('=');
    }
    return out;
}

std::string base64_encode(const std::string &data)
{
    return base64_encode(reinterpret_cast<const unsigned char *>(data.data()),
                         data.size());
}

std::string sha1(const std::string &data)
{
    auto rol = [](uint32_t v, int b)
    {
        return (v << b) | (v >> (32 - b));
    };

    std::vector<uint8_t> msg(data.begin(), data.end());
    const uint64_t bit_len = static_cast<uint64_t>(data.size()) * 8;
    msg.push_back(0x80);
    while (msg.size() % 64 != 56)
        msg.push_back(0x00);
    for (int i = 7; i >= 0; --i)
        msg.push_back(static_cast<uint8_t>((bit_len >> (i * 8)) & 0xFF));

    uint32_t h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE,
             h3 = 0x10325476, h4 = 0xC3D2E1F0;

    for (size_t chunk = 0; chunk < msg.size(); chunk += 64)
    {
        uint32_t w[80];
        for (int j = 0; j < 16; ++j)
        {
            w[j] = (static_cast<uint32_t>(msg[chunk + j * 4]) << 24) |
                   (static_cast<uint32_t>(msg[chunk + j * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(msg[chunk + j * 4 + 2]) << 8) |
                   static_cast<uint32_t>(msg[chunk + j * 4 + 3]);
        }
        for (int j = 16; j < 80; ++j)
            w[j] = rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);

        uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
        for (int j = 0; j < 80; ++j)
        {
            uint32_t f, k;
            if (j < 20)
            {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            }
            else if (j < 40)
            {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (j < 60)
            {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else
            {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            uint32_t tmp = rol(a, 5) + f + e + k + w[j];
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = tmp;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    std::string out(20, '\0');
    const uint32_t hs[5] = {h0, h1, h2, h3, h4};
    for (int i = 0; i < 5; ++i)
    {
        out[i * 4 + 0] = static_cast<char>((hs[i] >> 24) & 0xFF);
        out[i * 4 + 1] = static_cast<char>((hs[i] >> 16) & 0xFF);
        out[i * 4 + 2] = static_cast<char>((hs[i] >> 8) & 0xFF);
        out[i * 4 + 3] = static_cast<char>(hs[i] & 0xFF);
    }
    return out;
}

std::string status_text(int code)
{
    switch (code)
    {
    case 100:
        return "Continue";
    case 101:
        return "Switching Protocols";
    case 200:
        return "OK";
    case 201:
        return "Created";
    case 202:
        return "Accepted";
    case 204:
        return "No Content";
    case 206:
        return "Partial Content";
    case 301:
        return "Moved Permanently";
    case 302:
        return "Found";
    case 303:
        return "See Other";
    case 304:
        return "Not Modified";
    case 307:
        return "Temporary Redirect";
    case 308:
        return "Permanent Redirect";
    case 400:
        return "Bad Request";
    case 401:
        return "Unauthorized";
    case 403:
        return "Forbidden";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 408:
        return "Request Timeout";
    case 409:
        return "Conflict";
    case 411:
        return "Length Required";
    case 413:
        return "Payload Too Large";
    case 414:
        return "URI Too Long";
    case 415:
        return "Unsupported Media Type";
    case 426:
        return "Upgrade Required";
    case 429:
        return "Too Many Requests";
    case 431:
        return "Request Header Fields Too Large";
    case 500:
        return "Internal Server Error";
    case 501:
        return "Not Implemented";
    case 502:
        return "Bad Gateway";
    case 503:
        return "Service Unavailable";
    case 504:
        return "Gateway Timeout";
    default:
        return "";
    }
}

std::string http_date(std::time_t t)
{
    static const char *wdays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    static const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
                                  };

    std::tm tm_utc{};
#if defined(_WIN32)
    gmtime_s(&tm_utc, &t);
#else
    gmtime_r(&t, &tm_utc);
#endif

    char buf[64];
    std::snprintf(buf, sizeof(buf), "%s, %02d %s %04d %02d:%02d:%02d GMT",
                  wdays[tm_utc.tm_wday], tm_utc.tm_mday, months[tm_utc.tm_mon],
                  tm_utc.tm_year + 1900, tm_utc.tm_hour,
                  tm_utc.tm_min, tm_utc.tm_sec);
    return buf;
}

// ==================== Cookie ====================

std::string Cookie::to_string() const
{
    std::string out = name + "=" + value;
    if (!path.empty())
        out += "; Path=" + path;
    if (!domain.empty())
        out += "; Domain=" + domain;
    if (!expires.empty())
        out += "; Expires=" + expires;
    if (max_age >= 0)
        out += "; Max-Age=" + std::to_string(max_age);
    if (secure)
        out += "; Secure";
    if (http_only)
        out += "; HttpOnly";
    if (!same_site.empty())
        out += "; SameSite=" + same_site;
    return out;
}

// ==================== Header_get ====================

Header_get::Header_get(TCP::Base_Link &link, int timeout_ms, const Limits &limits)
{
    if (!link.valid())
        return;

    // 整个请求(请求行 + 请求头 + 请求体)的总超时
    const bool infinite = (timeout_ms <= 0);
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(infinite ? 0 : timeout_ms);

    auto remain = [&]() -> int
    {
        if (infinite)
            return 0;
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline)
            return -1;
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            deadline - now)
                        .count();
        return ms > 0 ? static_cast<int>(ms) : -1;
    };

    // ---- 请求行 ----
    std::string line;
    {
        int t = remain();
        if (t < 0)
        {
            error_status_ = 408;
            return;
        }
        TCP::ReadStatus st = link.Read_until("\r\n", t, limits.max_request_line, line);
        if (st == TCP::ReadStatus::Overflow)
        {
            error_status_ = 414; // 请求行(URI)过长
            return;
        }
        if (st == TCP::ReadStatus::Timeout)
        {
            error_status_ = 408; // 读取请求行超时
            return;
        }
        if (st != TCP::ReadStatus::Ok)
            return; // 连接已关闭:视为无请求
    }
    trim(line);

    // METHOD SP URL SP VERSION
    size_t sp1 = line.find(' ');
    if (sp1 == std::string::npos)
    {
        error_status_ = 400;
        return;
    }
    size_t sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos)
    {
        error_status_ = 400;
        return;
    }

    method = line.substr(0, sp1);
    raw_url = line.substr(sp1 + 1, sp2 - sp1 - 1);
    version = trim_copy(line.substr(sp2 + 1));
    if (method.empty() || version.empty())
    {
        error_status_ = 400;
        return;
    }
    /*
     * 方法与版本都只接受规范写法:
     *   - 方法必须是 token(否则不同实现对同一行会有不同切分);
     *   - 版本必须是 HTTP/1.0 或 HTTP/1.1,本服务器不支持更早/更新的协议,
     *     直接回 400 比按 1.1 语义猜更安全(避免版本降级走私)。
     */
    if (!is_token(method))
    {
        error_status_ = 400;
        return;
    }
    if (version != "HTTP/1.0" && version != "HTTP/1.1")
    {
        error_status_ = 400;
        return;
    }

    // ---- URL 与查询参数 ----
    size_t qpos = raw_url.find('?');
    if (qpos != std::string::npos)
    {
        url = url_decode(raw_url.substr(0, qpos));
        parse_query(raw_url.substr(qpos + 1), query);
    }
    else
    {
        url = url_decode(raw_url);
    }

    // ---- 请求头 ----
    size_t header_bytes = 0;
    while (true)
    {
        int t = remain();
        if (t < 0)
        {
            error_status_ = 408;
            return;
        }
        TCP::ReadStatus st = link.Read_until("\r\n", t, limits.max_header_line, line);
        if (st == TCP::ReadStatus::Overflow)
        {
            error_status_ = 431; // 请求头过大
            return;
        }
        if (st == TCP::ReadStatus::Timeout)
        {
            error_status_ = 408;
            return;
        }
        if (st != TCP::ReadStatus::Ok)
        {
            error_status_ = 400; // 请求头未结束就断开
            return;
        }

        // 空行 = 请求头结束(Read_until 返回的内容不含 CRLF,所以空串就是空行)
        if (line.empty())
            break;

        // RFC 7230:以空白字符开头的行是已废弃的 obs-fold(折行续写),
        // 服务器必须拒绝;否则会把一行拆成两次解析的差异当成走私入口
        if (line.front() == ' ' || line.front() == '\t')
        {
            error_status_ = 400;
            return;
        }

        header_bytes += line.size();
        if (headers.size() >= limits.max_header_count ||
                header_bytes > limits.max_header_bytes)
        {
            error_status_ = 431;
            return;
        }

        size_t colon = line.find(':');
        if (colon == std::string::npos || colon == 0)
        {
            error_status_ = 400; // 畸形(corrupt)的请求头行
            return;
        }
        // RFC 7230:字段名与冒号之间不允许出现空白;放过它会与代理的解析产生分歧
        if (line[colon - 1] == ' ' || line[colon - 1] == '\t')
        {
            error_status_ = 400;
            return;
        }
        std::string key = to_lower(line.substr(0, colon));
        std::string value = trim_copy(line.substr(colon + 1));
        if (!is_token(key))
        {
            error_status_ = 400;
            return;
        }
        /*
         * 定界头(Content-Length / Transfer-Encoding)重复出现时,
         * 不同实现对"用哪一个"的判断不同 —— 这就是请求走私。
         * 这里要求它们最多出现一次;两者同时出现的检查在读完头部后进行。
         */
        if (key == "content-length" || key == "transfer-encoding")
        {
            if (headers.find(key) != headers.end())
            {
                error_status_ = 400;
                return;
            }
        }
        if (key == "cookie")
        {
            // 允许出现多个 Cookie 头:用 "; " 连接后统一解析
            std::string &slot = headers[key];
            if (!slot.empty())
                slot += "; ";
            slot += value;
        }
        else
        {
            headers[key] = value;
        }
    }

    /*
     * ---- 报文定界校验 ----
     * 同时带 Content-Length 与 Transfer-Encoding 的请求必须拒绝(RFC 7230 §3.3.3):
     * 前端代理与后端对"以哪个为准"的理解不一致,就是最典型的请求走私条件。
     * 另外,Transfer-Encoding 只支持 chunked(最后一项),其它编码无法解码。
     */
    {
        auto cl = headers.find("content-length");
        auto te = headers.find("transfer-encoding");
        if (cl != headers.end() && te != headers.end())
        {
            error_status_ = 400;
            return;
        }
        if (te != headers.end())
        {
            const std::string value = to_lower(trim_copy(te->second));
            const size_t comma = value.find_last_of(',');
            const std::string last =
                trim_copy(comma == std::string::npos ? value : value.substr(comma + 1));
            if (last != "chunked")
            {
                error_status_ = 400; // 无法确定报文长度
                return;
            }
            if (comma != std::string::npos)
            {
                error_status_ = 501; // 还有其它传输编码,本服务器不支持
                return;
            }
        }
    }

    // ---- 请求体 ----
    int body_err = read_body(link, headers, body, deadline, infinite, limits);
    if (body_err != 0)
    {
        error_status_ = body_err;
        return;
    }

    // ---- Cookie ----
    auto ck = headers.find("cookie");
    if (ck != headers.end())
        parse_cookies(ck->second, cookies);
}

std::string Header_get::get(const std::string &key, const std::string &def) const
{
    auto it = headers.find(to_lower(key));
    return it == headers.end() ? def : it->second;
}

bool Header_get::has(const std::string &key) const
{
    return headers.find(to_lower(key)) != headers.end();
}

std::string Header_get::cookie(const std::string &name,
                               const std::string &def) const
{
    auto it = cookies.find(name);
    return it == cookies.end() ? def : it->second;
}

bool Header_get::has_cookie(const std::string &name) const
{
    return cookies.find(name) != cookies.end();
}

bool Header_get::is_websocket() const
{
    if (method != "GET")
        return false;
    // Upgrade / Connection 都是逗号分隔的 token 列表,按 token 判定
    if (!has_list_token(get("upgrade"), "websocket"))
        return false;
    return has_list_token(get("connection"), "upgrade");
}

bool Header_get::keep_alive() const
{
    const std::string conn = get("connection");
    if (version == "HTTP/1.0")
        return has_list_token(conn, "keep-alive");
    return !has_list_token(conn, "close");
}

// ==================== Header_send ====================

Header_send::Header_send(int status, std::string body,
                         const std::string &content_type)
    : status(status), body(std::move(body))
{
    headers["Content-Type"] = content_type;
}

void Header_send::set_header(const std::string &key, const std::string &value)
{
    headers[key] = value;
}

void Header_send::add_cookie(const Cookie &cookie)
{
    set_cookies.push_back(cookie.to_string());
}

void Header_send::add_cookie(const std::string &raw_set_cookie)
{
    set_cookies.push_back(raw_set_cookie);
}

void Header_send::delete_cookie(const std::string &name, const std::string &path)
{
    Cookie c(name, "");
    c.path = path;
    c.max_age = 0;
    c.expires = "Thu, 01 Jan 1970 00:00:00 GMT";
    set_cookies.push_back(c.to_string());
}

bool Header_send::has_header(const std::string &key) const
{
    const std::string want = to_lower(key);
    for (const auto &kv : headers)
    {
        if (to_lower(kv.first) == want)
            return true;
    }
    return false;
}

bool Header_send::is_chunked() const
{
    if (!streaming)
        return false;

    // 用户显式指定 Transfer-Encoding 时以其为准
    for (const auto &kv : headers)
    {
        if (to_lower(kv.first) == "transfer-encoding")
            return to_lower(kv.second).find("chunked") != std::string::npos;
    }
    // 显式给出 Content-Length 时按定长流式发送,不分块
    for (const auto &kv : headers)
    {
        if (to_lower(kv.first) == "content-length")
            return false;
    }
    if (!use_chunked)
        return false;
    // HTTP/1.0 不支持分块编码
    const Header_get *request = detail::current_request();
    if (request != nullptr ? request->version == "HTTP/1.0" : version == "HTTP/1.0")
        return false;
    return true;
}

bool Header_send::is_close_delimited() const
{
    // 既不分块也没有长度时,只能靠关闭连接告诉对端"响应体到此结束"
    return streaming && !is_chunked() && !has_header("content-length");
}

bool Header_send::is_head_request() const
{
    const Header_get *request = detail::current_request();
    return request != nullptr && request->method == "HEAD";
}

bool Header_send::body_suppressed() const
{
    // 1xx / 204 / 304 按规范不携带响应体
    if (status >= 100 && status < 200)
        return true;
    if (status == 204 || status == 304)
        return true;
    return is_head_request();
}

bool Header_send::will_reuse_connection() const
{
    // 响应体只能靠关闭连接定界时,必须关闭
    if (is_close_delimited())
        return false;

    // 框架层的 Keep-Alive 开关
    if (!detail::reuse_allowed())
        return false;

    // 客户端意愿:无请求上下文时按 HTTP/1.1 默认保持连接
    const Header_get *request = detail::current_request();
    if (request ? !request->keep_alive() : version == "HTTP/1.0")
        return false;

    // 处理器显式指定时以其为准
    return keep_alive_auto ? true : keep_alive;
}

std::string Header_send::serialize_head() const
{
    std::map<std::string, std::string> hdrs = headers;

    bool has_len = false, has_te = false, has_conn = false;
    for (const auto &kv : hdrs)
    {
        std::string k = to_lower(kv.first);
        if (k == "content-length")
            has_len = true;
        else if (k == "transfer-encoding")
            has_te = true;
        else if (k == "connection")
            has_conn = true;
    }

    const bool chunked = is_chunked();
    const bool close_delimited = streaming && !chunked && !has_len;
    const bool reuse = will_reuse_connection();

    if (!streaming)
    {
        // 一次性发送:长度已知,自动补 Content-Length。
        // HEAD 响应保留与 GET 相同的长度(正文由 serialize 丢弃);
        // 204/304/1xx 按规范不携带响应体,也不输出长度
        const bool no_body_status = status == 204 || status == 304 ||
                                    (status >= 100 && status < 200);
        if (!has_len && !has_te && (!no_body_status || is_head_request()))
            hdrs["Content-Length"] = std::to_string(body.size());
    }
    else if (chunked)
    {
        // 分块编码与定长互斥:移除用户误设的 Content-Length
        for (auto it = hdrs.begin(); it != hdrs.end();)
        {
            if (to_lower(it->first) == "content-length")
                it = hdrs.erase(it);
            else
                ++it;
        }
        if (!has_te)
            hdrs["Transfer-Encoding"] = "chunked";
    }
    // 定长流式:沿用用户设置的 Content-Length,无需额外头

    if (close_delimited)
    {
        // 必须让对端通过连接关闭判定结束,不能被 keep-alive 覆盖
        for (auto it = hdrs.begin(); it != hdrs.end();)
        {
            if (to_lower(it->first) == "connection")
                it = hdrs.erase(it);
            else
                ++it;
        }
        hdrs["Connection"] = "close";
    }
    else if (!has_conn)
    {
        hdrs["Connection"] = reuse ? "keep-alive" : "close";
    }
    else if (!reuse)
    {
        // 需要关闭连接时,不允许留着误导对端的 keep-alive 值
        for (auto &kv : hdrs)
        {
            if (to_lower(kv.first) == "connection" &&
                    to_lower(kv.second).find("keep-alive") != std::string::npos)
                kv.second = "close";
        }
    }

    std::string out;
    out.reserve(256);
    /*
     * 输出前统一清洗:状态短语、头部名、头部值、Set-Cookie 都可能来自脚本
     * (HTTP.send.header / status(code, reason) / cookie(...)),其中可能夹带
     * CR/LF。不清洗就会形成 HTTP 响应拆分(响应头注入 / 缓存投毒)。
     * 这里是所有响应文本的唯一出口,放在这一层兜底最可靠。
     */
    append_header_safe(out, version, false);
    out += ' ';
    out += std::to_string(status);
    out += ' ';
    append_header_safe(out, response_reason(*this), true);
    out += "\r\n";
    for (const auto &kv : hdrs)
    {
        const std::size_t before = out.size();
        append_header_safe(out, kv.first, false);
        if (out.size() == before)
            continue; // 清洗后没有合法名字的头直接丢弃(避免输出 ": value")
        out += ": ";
        append_header_safe(out, kv.second, true);
        out += "\r\n";
    }
    for (const auto &sc : set_cookies)
    {
        out += "Set-Cookie: ";
        append_header_safe(out, sc, true);
        out += "\r\n";
    }
    out += "\r\n";
    return out;
}

std::string Header_send::serialize() const
{
    // HEAD / 204 / 304 / 1xx 不发送响应体,头中的长度信息仍保留
    if (body_suppressed())
        return serialize_head();
    // 流式响应的分块封装由 send_chunk 负责,这里只拼头部与原始 body
    return serialize_head() + body;
}

bool Header_send::send_head(TCP::Base_Link &link) const
{
    // 重复调用不重复发送
    if (head_sent_)
        return link.valid();

    if (!link.valid())
        return false;

    const std::string head = serialize_head();
    link.Send_str(head);

    head_sent_ = true;
    streamed_bytes_ = 0;

    // 响应头日志:状态码 + 头部大小 + 定界方式 + 是否复用连接 + 目标地址
    if (access_log_on())
    {
        const std::string mode = is_chunked() ? "chunked"
                                 : is_close_delimited() ? "close-delimited"
                                 : "fixed-length";
        std::string message = response_log_head(*this, "Response head: ");
        message += " (";
        message += std::to_string(head.size());
        message += " bytes, mode: ";
        message += mode;
        message += ", keep-alive: ";
        message += will_reuse_connection() ? "yes" : "no";
        message += ", peer: ";
        message += link.get_peer();
        message += ")";
        Log::access(std::move(message), status_color(status), "HTTP");
    }
    return link.valid();
}

bool Header_send::send_chunk(TCP::Base_Link &link, const char *data, size_t len) const
{
    if (!head_sent_)
    {
        // 首次写入时自动切换为流式,避免头部写出定长长度后又追加数据
        streaming = true;
        if (!send_head(link))
            return false;
    }
    if (!link.valid())
        return false;

    // 空块会被对端当作分块结束标记,这里直接跳过
    if (len == 0)
        return true;
    if (data == nullptr)
        return false;

    // HEAD / 204 / 304:只累计字节数,不写出任何数据
    if (body_suppressed())
    {
        streamed_bytes_ += len;
        return true;
    }

    std::string out;
    if (is_chunked())
    {
        // 分块封装:<十六进制长度>CRLF <数据> CRLF
        char size_line[32];
        std::snprintf(size_line, sizeof(size_line), "%llx\r\n",
                      static_cast<unsigned long long>(len));
        out.reserve(std::strlen(size_line) + len + 2);
        out += size_line;
        out.append(data, len);
        out += "\r\n";
    }
    else
    {
        out.assign(data, len);
    }

    link.Send_str(out);
    streamed_bytes_ += len;
    return link.valid();
}

bool Header_send::send_chunk(TCP::Base_Link &link, const std::string &data) const
{
    return send_chunk(link, data.data(), data.size());
}

bool Header_send::send_chunk(TCP::Base_Link &link, const std::vector<char> &data) const
{
    return send_chunk(link, data.data(), data.size());
}

bool Header_send::end_stream(TCP::Base_Link &link) const
{
    if (!link.valid())
        return false;

    if (!head_sent_ && !send_head(link))
        return false;

    // 分块模式补发结束块;定长 / 关闭定界模式无需额外字节
    // (无响应体的响应不应发送数据块,否则对端会把它当成正文)
    if (is_chunked() && !body_suppressed())
        link.Send_str("0\r\n\r\n");

    // 响应日志:状态码 + 流式字节数 + 定界方式 + 是否复用连接 + 目标地址
    if (access_log_on())
    {
        const std::string mode = is_chunked() ? "chunked"
                                 : is_close_delimited() ? "close-delimited"
                                 : "fixed-length";
        std::string message = response_log_head(*this, "Response: ");
        message += " (";
        message += std::to_string(streamed_bytes_);
        message += " bytes streamed, mode: ";
        message += mode;
        message += ", keep-alive: ";
        message += will_reuse_connection() ? "yes" : "no";
        message += ", peer: ";
        message += link.get_peer();
        message += ")";
        Log::access(std::move(message), status_color(status), "HTTP");
    }

    // 复位内部状态,便于同一个对象继续发送下一个响应
    head_sent_ = false;
    streamed_bytes_ = 0;
    return link.valid();
}

bool Header_send::send_stream(
    TCP::Base_Link &link,
    const std::function<bool(std::string &chunk)> &producer) const
{
    if (!send_head(link))
        return false;

    bool interrupted = false;
    std::string chunk;
    while (producer)
    {
        chunk.clear();
        bool more = false;
        try
        {
            more = producer(chunk);
        }
        catch (const std::exception &e)
        {
            Log::error(std::string("Stream producer error: ") + e.what());
            interrupted = true;
            break;
        }
        catch (...)
        {
            Log::error("Stream producer error: unknown exception");
            interrupted = true;
            break;
        }

        if (!chunk.empty() && !send_chunk(link, chunk))
        {
            interrupted = true;
            break;
        }
        if (!more)
            break;
    }

    if (interrupted)
    {
        // 流被截断:不补发结束块,让对端能察觉响应不完整
        head_sent_ = false;
        streamed_bytes_ = 0;
        return false;
    }
    return end_stream(link);
}

void Header_send::send(TCP::Base_Link &link) const
{
    // 非流式:头部与 body 一次写出,由序列化保证长度正确
    if (!streaming)
    {
        link.Send_str(serialize());

        // 响应日志:状态码 + 响应体大小 + 是否复用连接 + 目标地址
        if (access_log_on())
        {
            std::string message = response_log_head(*this, "Response: ");
            message += " (";
            message += std::to_string(body.size());
            message += " bytes, keep-alive: ";
            message += will_reuse_connection() ? "yes" : "no";
            message += ", peer: ";
            message += link.get_peer();
            message += ")";
            Log::access(std::move(message), status_color(status), "HTTP");
        }
        return;
    }

    // 流式:发头 + body(作为首段数据) + 收尾
    if (!send_head(link))
        return;
    if (!body.empty() && !send_chunk(link, body))
        return;
    end_stream(link);
}


Header_send Header_send::Text(const std::string &body, int status)
{
    return Header_send(status, body, "text/plain; charset=utf-8");
}

Header_send Header_send::Html(const std::string &body, int status)
{
    return Header_send(status, body, "text/html; charset=utf-8");
}

Header_send Header_send::Json(const std::string &body, int status)
{
    return Header_send(status, body, "application/json; charset=utf-8");
}

Header_send Header_send::Status(int status, const std::string &message)
{
    std::string msg = message.empty() ? HTTP::status_text(status) : message;
    return Header_send(status, msg, "text/plain; charset=utf-8");
}

Header_send Header_send::Redirect(const std::string &location, int status)
{
    Header_send res(status, "", "text/plain; charset=utf-8");
    res.set_header("Location", location);
    return res;
}

Header_send Header_send::Stream(const std::string &content_type, int status)
{
    Header_send res(status, "", content_type);
    res.streaming = true;
    res.use_chunked = true;
    return res;
}

Header_send Header_send::EventStream(int status)
{
    Header_send res = Stream("text/event-stream; charset=utf-8", status);
    res.set_header("Cache-Control", "no-cache");
    // 关闭 Nginx 等反向代理的响应缓冲,保证事件及时到达客户端
    res.set_header("X-Accel-Buffering", "no");
    res.keep_alive = true; // SSE 是长连接,默认复用连接
    return res;
}

Header_send Header_send::Download(const std::string &content_type,
                                  unsigned long long total_size,
                                  const std::string &filename)
{
    Header_send res = Stream(content_type, 200);
    res.use_chunked = false; // 总长度已知:使用定长流式,不分块
    res.set_header("Content-Length", std::to_string(total_size));
    if (!filename.empty())
        res.set_header("Content-Disposition",
                       "attachment; filename=\"" + filename + "\"");
    return res;
}

// ==================== Distributor ====================

Distributor::Distributor(TCP::Server &server) : server_(&server) {}

Distributor::~Distributor()
{
    stop();
}

void Distributor::register_route(std::map<std::string, Route_entry> &table,
                                 const std::string &path, std::shared_ptr<Router> router,
                                 bool websocket)
{
    const char *kind = websocket ? "WebSocket" : "HTTP";
    if (!router)
    {
        Log::warning(std::string("Distributor: null ") + kind + " router for path \"" +
                     Log::sanitize(path) + "\" ignored");
        return;
    }

    // 规范化路径:空串按根路径处理,缺少开头的 '/' 时补上
    // (否则这条路由永远不会被请求 url 命中,且没有任何提示)
    std::string key = trim_copy(path);
    if (key.empty())
        key = "/";
    else if (key.front() != '/')
        key.insert(key.begin(), '/');

    if (key != path)
    {
        Log::warning("Distributor: route path \"" + Log::sanitize(path) +
                     "\" normalized to \"" + Log::sanitize(key) + "\"");
    }

    Route_entry &entry = table[key];
    std::shared_ptr<Router> &slot = websocket ? entry.websocket : entry.router;
    if (slot)
    {
        // 同一路径、同一类型重复注册:只保留最后一次,但必须让人看到
        Log::warning(std::string("Distributor: ") + kind + " router for path \"" +
                     Log::sanitize(key) + "\" replaced by a later registration");
    }
    slot = std::move(router);
}

void Distributor::add_router(const std::string &path,
                             std::shared_ptr<Router> router)
{
    register_route(routers_, path, std::move(router), false);
}

void Distributor::add_router(const std::string &host, const std::string &path,
                             std::shared_ptr<Router> router)
{
    const std::string key = normalize_host(host);
    if (key.empty())
    {
        // 空域名等价于"默认域名表",不要注册到一张永远匹配不到的空域名表里
        Log::warning("Distributor: empty host means the default table (path \"" +
                     Log::sanitize(path) + "\")");
        register_route(routers_, path, std::move(router), false);
        return;
    }
    register_route(hosts_[key].routers, path, std::move(router), false);
}

void Distributor::add_websocket_router(const std::string &path, WsHandler handler)
{
    if (!handler)
    {
        Log::warning("Distributor: null WebSocket handler for path \"" +
                     Log::sanitize(path) + "\" ignored");
        return;
    }
    register_route(routers_, path, std::make_shared<WsRouter>(std::move(handler)), true);
}

void Distributor::add_websocket_router(const std::string &host, const std::string &path,
                                       WsHandler handler)
{
    if (!handler)
    {
        Log::warning("Distributor: null WebSocket handler for path \"" +
                     Log::sanitize(path) + "\" ignored");
        return;
    }
    const std::string key = normalize_host(host);
    if (key.empty())
    {
        Log::warning("Distributor: empty host means the default table (path \"" +
                     Log::sanitize(path) + "\")");
        register_route(routers_, path, std::make_shared<WsRouter>(std::move(handler)), true);
        return;
    }
    register_route(hosts_[key].routers, path,
                   std::make_shared<WsRouter>(std::move(handler)), true);
}

void Distributor::set_not_found_router(std::shared_ptr<Router> router)
{
    not_found_ = std::move(router);
}

void Distributor::set_not_found_router(const std::string &host,
                                       std::shared_ptr<Router> router)
{
    const std::string key = normalize_host(host);
    if (key.empty())
    {
        // 与 add_router 一致:空域名就是默认表,避免兜底处理器挂在不可达的表上
        Log::warning("Distributor: empty host means the default table (not-found router)");
        not_found_ = std::move(router);
        return;
    }
    hosts_[key].not_found = std::move(router);
}

std::string Distributor::normalize_host(const std::string &host)
{
    std::string h = to_lower(trim_copy(host));
    if (!h.empty() && h.front() == '[')
    {
        // IPv6 字面量:[::1]:8080 -> ::1
        size_t r = h.find(']');
        if (r != std::string::npos)
            h = h.substr(1, r - 1);
    }
    else
    {
        // 去掉端口:example.com:8080 -> example.com
        size_t c = h.find(':');
        if (c != std::string::npos)
            h = h.substr(0, c);
    }
    while (!h.empty() && h.back() == '.') // 去掉结尾的点
        h.pop_back();
    return h;
}

void Distributor::set_websocket_handler(WsHandler handler)
{
    ws_handler_ = std::move(handler);
}

void Distributor::set_type_classifier(TypeClassifier classifier)
{
    type_classifier_ = std::move(classifier);
}

void Distributor::set_read_timeout_ms(int ms)
{
    read_timeout_ms_ = ms;
}

void Distributor::set_limits(const Limits &limits)
{
    limits_ = limits;
}

void Distributor::set_keep_alive(bool enable)
{
    keep_alive_enabled_ = enable;
}

void Distributor::set_tls(std::shared_ptr<TLS::Context> ctx, int handshake_timeout_ms)
{
    tls_ctx_ = std::move(ctx);
    tls_handshake_timeout_ms_ = handshake_timeout_ms;
}

bool Distributor::tls_enabled() const noexcept
{
    return static_cast<bool>(tls_ctx_);
}

bool Distributor::establish_tls(TCP::Base_Link &link)
{
    // 复制一份上下文引用,避免与 set_tls 竞争
    std::shared_ptr<TLS::Context> ctx = tls_ctx_;
    if (!ctx)
        return true; // 未启用 TLS

    std::string error;
    if (!link.start_tls(std::move(ctx), tls_handshake_timeout_ms_, &error))
    {
        // 把 OpenSSL 的具体失败原因写进日志,便于排查证书 / 协议不匹配
        Log::warning("TLS handshake failed: " + link.get_peer() +
                     (error.empty() ? std::string() : " (" + error + ")"));
        return false;
    }
    return true;
}

void Distributor::add_filter(std::shared_ptr<RequestFilter> filter)
{
    filters_.push_back(std::move(filter));
}

void Distributor::add_filter(FilterFunc filter)
{
    filters_.push_back(std::make_shared<FuncFilter>(std::move(filter)));
}

void Distributor::clear_filters()
{
    filters_.clear();
}

FilterAction Distributor::run_filters(Header_get &request, TCP::Base_Link &link,
                                      Header_send &response)
{
    for (auto &filter : filters_)
    {
        if (!filter)
            continue;
        try
        {
            const FilterAction result = filter->inspect(request, link, response);
            if (result != FilterAction::Continue)
                return result;
        }
        catch (const std::exception &e)
        {
            // fail-closed:检查器自身出错时拒绝该请求,避免绕过安全校验
            Log::error(std::string("Request filter error: ") + e.what());
            response = Header_send::Status(500, "Internal Server Error");
            return FilterAction::Block;
        }
    }
    return FilterAction::Continue;
}

bool Distributor::running() const noexcept
{
    return running_.load(std::memory_order_acquire);
}

void Distributor::start()
{
    if (!server_ || !server_->valid())
    {
        Log::error("Distributor: server is not listening.");
        return;
    }
    if (running_.exchange(true, std::memory_order_acq_rel))
        return; // 已在运行

    accept_thread_ = std::thread([this]
    { accept_loop(); });
    Log::log("Distributor started.", Log::Color::LightGreen, "HTTP");
}

void Distributor::stop()
{
    bool was_running = running_.exchange(false, std::memory_order_acq_rel);
    if (!was_running && !accept_thread_.joinable())
        return;

    // 1) 关闭监听套接字,唤醒阻塞在 accept() 的线程
    if (server_)
        server_->Close();
    if (accept_thread_.joinable())
        accept_thread_.join();

    // 2) 关闭所有活动连接,唤醒阻塞在 recv() 的工作线程
    {
        std::lock_guard<std::mutex> lk(clients_mtx_);
        for (auto &kv : clients_)
            kv.second->Close();
    }

    // 3) 等待所有工作线程结束
    {
        std::lock_guard<std::mutex> lk(workers_mtx_);
        for (auto &w : workers_)
            if (w.thread.joinable())
                w.thread.join();
        workers_.clear();
    }

    Log::log("Distributor stopped.", Log::Color::Yellow, "HTTP");
}

size_t Distributor::active_clients()
{
    std::lock_guard<std::mutex> lk(clients_mtx_);
    return clients_.size();
}

void Distributor::accept_loop()
{
    while (running_.load(std::memory_order_acquire))
    {
        TCP::Base_Link link = server_->get_link();
        if (!link.valid())
            break; // 服务器已关闭或出错

        auto shared = std::make_shared<TCP::Base_Link>(std::move(link));

        // 登记活动连接(便于 stop 时统一关闭)
        size_t id = next_client_id_.fetch_add(1, std::memory_order_relaxed);
        {
            std::lock_guard<std::mutex> lk(clients_mtx_);
            clients_[id] = shared;
        }

        auto done = std::make_shared<std::atomic<bool>>(false);

        std::lock_guard<std::mutex> lk(workers_mtx_);
        // 回收已结束的工作线程
        for (auto it = workers_.begin(); it != workers_.end();)
        {
            if (it->done->load(std::memory_order_acquire))
            {
                if (it->thread.joinable())
                    it->thread.join();
                it = workers_.erase(it);
            }
            else
            {
                ++it;
            }
        }
        // 启动新的工作线程
        workers_.push_back(Worker{
            std::thread([this, shared, id, done]()
            {
                const auto begin = std::chrono::steady_clock::now();
                const std::string peer = shared->get_peer();

                // 启用 TLS 时先完成握手(失败则直接丢弃连接)
                if (establish_tls(*shared))
                {
                    // 连接建立日志:IP:端口 + 协议 + 当前活动连接数
                    if (access_log_on())
                    {
                        Log::access("Connection established: " + peer + " (protocol: " +
                                    protocol_name(*shared) + ", active: " +
                                    std::to_string(active_clients()) + ")",
                                    Log::Color::LightGreen, "CONN");
                    }

                    handle_connection(shared);

                    // 连接断开日志:IP:端口 + 存活时长 + 剩余活动连接数
                    if (access_log_on())
                    {
                        Log::access("Connection closed: " + peer + " (duration: " +
                                    format_duration(std::chrono::steady_clock::now() - begin) +
                                    ", active: " +
                                    std::to_string(active_clients() - 1) + ")",
                                    Log::Color::DarkGray, "CONN");
                    }
                }

                {
                    std::lock_guard<std::mutex> cl(clients_mtx_);
                    clients_.erase(id);
                }
                done->store(true, std::memory_order_release);
            }),
            done});
    }
}

const Distributor::HostTable *Distributor::find_host_table(const std::string &host) const
{
    if (host.empty())
        return nullptr;

    // 1) 精确域名:优先级最高
    auto it = hosts_.find(host);
    if (it != hosts_.end())
        return &it->second;

    // 2) 通配子域:*.example.com
    //    多个通配模式可能同时命中(例如 *.test 与 *.wild.test 都能匹配
    //    a.wild.test),必须取后缀最长的那条 —— 也就是最具体的一条。
    //    只看"第一个命中"会让结果取决于 map 的字典序,配置一多就不可预期。
    const HostTable *best = nullptr;
    std::size_t best_suffix = 0;
    for (const auto &kv : hosts_)
    {
        const std::string &pattern = kv.first;
        if (pattern.size() <= 2 || pattern[0] != '*' || pattern[1] != '.')
            continue;

        const std::string suffix = pattern.substr(1); // ".example.com"
        if (host.size() <= suffix.size())
            continue; // 至少要有一个标签,且不能是空标签
        if (host.compare(host.size() - suffix.size(), suffix.size(), suffix) != 0)
            continue;
        if (suffix.size() > best_suffix)
        {
            best_suffix = suffix.size();
            best = &kv.second;
        }
    }
    return best;
}

const Distributor::Route_entry *Distributor::find_route(
    const std::map<std::string, Route_entry> &routers, const std::string &url,
    std::string *path) const
{
    // 1) 精确匹配优先(以 '/' 结尾的路径也可能是别人请求的精确 url)
    auto it = routers.find(url);
    if (it != routers.end())
    {
        if (path)
            *path = it->first;
        return &it->second;
    }

    // 2) 前缀匹配(只有以 '/' 结尾的路径才是前缀路由),取最长的一条
    const Route_entry *best = nullptr;
    const std::string *best_path = nullptr;
    std::size_t best_len = 0;
    for (const auto &kv : routers)
    {
        const std::string &candidate = kv.first;
        if (candidate.empty() || candidate.back() != '/')
            continue;
        if (candidate.size() <= best_len)
            continue;
        if (url.compare(0, candidate.size(), candidate) != 0)
            continue;
        best_len = candidate.size();
        best = &kv.second;
        best_path = &kv.first;
    }
    if (best && path)
        *path = *best_path;
    return best;
}

Distributor::RouteMatch Distributor::match_route(const std::string &host,
        const std::string &url, RequestType type) const
{
    RouteMatch match;

    // 先看有没有该域名的专属表;命中后就不再回退到默认表
    const HostTable *table = find_host_table(host);
    if (table)
    {
        match.host_table = true;
        match.not_found = table->not_found;
        if (const Route_entry *entry = find_route(table->routers, url, &match.path))
        {
            // 路径命中后按请求类型取处理器;类型不匹配时留空,交给兜底处理器
            match.path_matched = true;
            match.router = entry->pick(type);
        }
        return match;
    }

    // 无专属表(域名未注册/无 Host 头)-> 默认表,对任意 Host 生效
    match.not_found = not_found_;
    if (const Route_entry *entry = find_route(routers_, url, &match.path))
    {
        match.path_matched = true;
        match.router = entry->pick(type);
    }
    return match;
}

void Distributor::handle_connection(std::shared_ptr<TCP::Base_Link> link)
{
    // 供 Header_send 自动生成 Connection 头:框架未启用 Keep-Alive 时一律 close
    detail::set_reuse_allowed(keep_alive_enabled_);

    while (true)
    {
        // 带总超时与解析上限地读取一个请求(防止 Slowloris / 内存耗尽)
        Header_get request(*link, read_timeout_ms_, limits_);

        // 解析失败:回应对应错误并优雅关闭连接
        if (request.error() != 0)
        {
            send_and_close(*link, Header_send::Status(request.error()));
            return;
        }

        // 未读到请求(对端正常关闭或空闲断开)
        if (request.method.empty())
            return;

        // 让 Header_send 能感知 HEAD 请求与客户端连接意愿
        RequestScope scope(&request);

        // 0) 判定请求类型(默认:WebSocket 升级 -> WebSocket,其余 -> Http)
        RequestType type = type_classifier_
                           ? type_classifier_(request)
                           : (request.is_websocket() ? RequestType::WebSocket
                              : RequestType::Http);

        // 1) 请求检查:任一过滤器拦截,立即回应并结束
        Header_send blocked;
        const FilterAction filter_action = run_filters(request, *link, blocked);
        if (filter_action != FilterAction::Continue)
        {
            if (access_log_on())
            {
                const std::string what = (filter_action == FilterAction::Close)
                                         ? "Request dropped: "
                                         : "Request blocked: ";
                const std::string tail = (filter_action == FilterAction::Close)
                                         ? " -> connection closed, peer: "
                                         : " -> " + std::to_string(blocked.status) +
                  ", peer: ";
                // 方法 / URL 来自网络:清洗后再进日志(避免日志注入)
                std::string message = what;
                Log::append_sanitized(message, request.method);
                message += ' ';
                Log::append_sanitized(message, request.raw_url);
                message += tail;
                message += link->get_peer();
                Log::access(std::move(message), Log::Color::Yellow, "HTTP");
            }
            if (filter_action == FilterAction::Block)
                send_and_close(*link, blocked); // 拦截:回应后断开
            else
                link->Close(); // 静默丢弃:不发送任何响应,直接断开
            return;
        }

        // 2) 规范化 Host,再按"域名 + URL + 请求类型"匹配路由
        //    (域名专属表命中后不再回退默认表;未命中域名时用默认表;
        //     路径命中但没有该类型的处理器时,处理器留空并交给兜底处理器)
        RouteMatch match = match_route(normalize_host(request.get("host")), request.url, type);

        // 3) 访问日志:请求方法 + 目录(路径) + 请求类型 + Host + 来源 + 路由结果
        if (access_log_on())
        {
            // 路由结果写清楚是"命中了哪张表的哪条路径",还是"路径命中但类型不匹配",
            // 避免看到 404 时无法判断是域名、路径还是请求类型的问题
            std::string route_state;
            if (match.router)
            {
                route_state = match.host_table ? "matched host " : "matched default ";
                Log::append_sanitized(route_state, match.path);
            }
            else if (match.path_matched)
            {
                route_state = match.host_table ? "host " : "default ";
                Log::append_sanitized(route_state, match.path);
                route_state += " has no ";
                route_state += request_type_name(type);
                route_state += " handler";
            }
            else
            {
                route_state = match.host_table ? "no route in host table" : "no route";
            }

            // 方法 / URL / Host 都来自网络:压成单行,避免换行伪造额外的日志行
            const std::string host_text = request.get("host");
            std::string message;
            message.reserve(160);
            Log::append_sanitized(message, request.method);
            message += ' ';
            Log::append_sanitized(message, request.raw_url);
            message += " [";
            message += request_type_name(type);
            message += "] path: ";
            Log::append_sanitized(message, request.url);
            message += " Host: ";
            if (host_text.empty())
                message += '-';
            else
                Log::append_sanitized(message, host_text);
            message += " peer: ";
            message += link->get_peer();
            message += " route: ";
            message += route_state;
            message += " body: ";
            message += std::to_string(request.body.size());
            message += " bytes";
            Log::access(std::move(message), Log::Color::LightGray, "HTTP");
        }

        // 4) 分发给对应的处理入口
        bool reusable = false;
        switch (type)
        {
        case RequestType::WebSocket:
            reusable = dispatch_websocket(link, request, match);
            break;
        case RequestType::Custom:
            reusable = dispatch_custom(link, request, match);
            break;
        case RequestType::Http:
        default:
            reusable = dispatch_http(link, request, match);
            break;
        }

        // 5) 决定是否在同一连接上继续处理下一个请求(Keep-Alive)
        if (!reusable || !keep_alive_enabled_ || !request.keep_alive() ||
                !link->valid())
        {
            link->Close();
            return;
        }
    }
}

bool Distributor::dispatch_http(std::shared_ptr<TCP::Base_Link> &link,
                                const Header_get &request,
                                const RouteMatch &match)
{
    try
    {
        // match.router 已按请求类型过滤:非空就代表它支持 Http
        if (match.router)
        {
            match.router->handle_request(*link, request);
        }
        else if (match.not_found && match.not_found->supports(RequestType::Http))
        {
            // 兜底处理器只在它声明处理 Http 时才接管,避免调用到空实现而让
            // 客户端收不到任何响应
            match.not_found->handle_request(*link, request);
        }
        else
        {
            Header_send::Status(404).send(*link);
        }
    }
    catch (const std::exception &e)
    {
        Log::error(std::string("HTTP handler error: ") + e.what());
        link->Close();
        return false;
    }

    // 是否复用连接由 handle_connection 统一决定
    return true;
}

bool Distributor::dispatch_websocket(std::shared_ptr<TCP::Base_Link> &link,
                                     const Header_get &request,
                                     const RouteMatch &match)
{
    // 处理器选择顺序(三种来源统一在这里决定,避免各分支各写一套):
    //   ① 路径命中的、支持 WebSocket 的处理器
    //   ② 该域名的兜底处理器(仅当它支持 WebSocket,即配置了 websocket 脚本)
    //   ③ 全局 WebSocket 处理器(向后兼容的老接口)
    //   ④ 都没有 -> 404
    std::shared_ptr<Router> router = match.router;
    WsHandler handler;
    if (!router)
    {
        if (match.not_found && match.not_found->supports(RequestType::WebSocket))
            router = match.not_found;
        else if (ws_handler_)
            handler = ws_handler_;
    }

    if (!router && !handler)
    {
        Log::warning("WebSocket request has no handler: " + Log::sanitize(request.url) +
                     " (peer: " + link->get_peer() + ")");
        send_and_close(*link, Header_send::Status(404));
        return false;
    }

    if (!WebSocket::Handshake(*link, request))
    {
        link->Close();
        return false;
    }

    WebSocket ws(*link);
    try
    {
        if (router)
            router->handle_websocket(ws, request);
        else
            handler(ws, request);
    }
    catch (const std::exception &e)
    {
        Log::error(std::string("WebSocket handler error: ") + e.what());
    }
    ws.Close();
    link->Close();
    return false; // 连接已升级为 WebSocket,不再复用为 HTTP
}

bool Distributor::dispatch_custom(std::shared_ptr<TCP::Base_Link> &link,
                                  const Header_get &request,
                                  const RouteMatch &match)
{
    // 与 HTTP / WebSocket 相同的规则:谁声明支持 Custom,谁处理;
    // 都没有则 404。不再把普通 HTTP 处理器误当成 Custom 处理器调用
    bool handled = false;
    if (match.router)
    {
        handled = match.router->handle_custom(*link, request);
    }
    if (!handled && match.not_found && match.not_found->supports(RequestType::Custom))
    {
        handled = match.not_found->handle_custom(*link, request);
    }
    if (!handled)
        Header_send::Status(404).send(*link);

    link->Close();
    return false; // 自定义协议通常独占连接,不复用
}

void Distributor::send_and_close(TCP::Base_Link &link, Header_send response)
{
    response.keep_alive = false;      // 错误/拦截响应不保持连接
    response.keep_alive_auto = false; // 即使客户端希望复用也强制关闭
    response.send(link);
    link.Shutdown_send(); // 发出 FIN,告知对端不再发送
    link.Drain(500);      // 短暂排空未读数据,避免 RST 冲掉响应
    link.Close();
}
} // namespace HTTP