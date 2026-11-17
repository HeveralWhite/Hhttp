#ifndef HTTP_H
#define HTTP_H
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <ctime>
#include <utility>

#include "TCP.h"

// 前向声明:TLS 上下文的完整定义在 TLS.h 中
// (避免 HTTP 层暴露 TLS/Asio 相关头文件,也避免循环包含)
namespace TLS
{
class Context;
}


namespace HTTP
{
// 前向声明:完整定义见 WebSocket.h(避免头文件循环包含)
class WebSocket;

// ==================== 工具函数 ====================

/*
 *@brief URL 解码:将 %XX 转为字节,'+' 转为空格
 */
std::string url_decode(const std::string &str);
/*
 *@brief URL 编码
 */
std::string url_encode(const std::string &str);
/*
 *@brief 返回字符串的小写副本
 */
std::string to_lower(std::string str);
/*
 *@brief 返回去除首尾空白后的字符串副本
 */
std::string trim_copy(std::string str);
/*
 *@brief Base64 编码
 */
std::string base64_encode(const unsigned char *data, size_t len);
std::string base64_encode(const std::string &data);
/*
 *@brief SHA-1 摘要(返回 20 字节原始数据,非十六进制字符串)
 */
std::string sha1(const std::string &data);
/*
 *@brief 根据状态码返回原因短语,例如 200 -> "OK"
 */
std::string status_text(int code);
/*
 *@brief 生成 HTTP 日期字符串(RFC 1123),例如 "Wed, 21 Oct 2015 07:28:00 GMT"
 *@param t UTC 时间戳(秒),默认当前时间,常用于 Cookie 的 Expires
 */
std::string http_date(std::time_t t = std::time(nullptr));

// ==================== 访问日志 ====================

/*
 *@brief 访问日志是否开启(默认开启)
 */
bool access_log_enabled() noexcept;
/*
 *@brief 打开/关闭访问日志
 *@param enable true 输出(默认)，false 关闭
 *@note  全局开关，对所有 Distributor 实例生效，线程安全;
 *       访问日志包含:连接建立/断开(IP:端口)、HTTP 请求(方法/路径/Host/类型)、
 *       HTTP 响应(状态码/字节数)、WebSocket 连接建立/关闭
 */
void set_access_log(bool enable);

// ==================== 解析限制 ====================

/*
 *@struct Limits
 *@brief 请求解析的资源上限,用于防御 Slowloris / 超大报文等 DoS 攻击
 */
struct Limits
{
    size_t max_request_line = 8 * 1024;      ///< 请求行最大字节数
    size_t max_header_line = 8 * 1024;       ///< 单个请求头行最大字节数
    size_t max_header_count = 100;           ///< 请求头最大数量
    size_t max_header_bytes = 64 * 1024;     ///< 请求头总字节数上限
    size_t max_body_bytes = 8 * 1024 * 1024; ///< 请求体最大字节数
};

// ==================== 请求 ====================

/*
 *@struct Header_get
 *@brief HTTP请求结构体(请求行 + 请求头 + 请求体)
 */
struct Header_get
{
    std::string method;                         ///< 请求方法
    std::string url;                            ///< 解码后的路径(不含查询串)
    std::string raw_url;                        ///< 原始请求目标
    std::map<std::string, std::string> query;   ///< 查询参数(已解码)
    std::string version;                        ///< HTTP 版本
    std::map<std::string, std::string> headers; ///< 请求头(key 统一小写)
    std::map<std::string, std::string> cookies; ///< Cookie 键值对(已解析)
    std::string body;                           ///< 请求体
    int error_status_ = 0;                      ///< 解析错误码(0 表示正常)

    Header_get() = default;
    /*
     *@brief 从 TCP 连接解析一个 HTTP 请求
     *@param link 已建立连接的 Base_Link
     *@param timeout_ms 整个请求(请求行 + 请求头 + 请求体)的总超时(毫秒),
     *                  0 表示无限等待(不推荐,易受 Slowloris 攻击)
     *@param limits 解析资源上限,用于防御超长请求行/超多请求头/超大请求体
     *@note  解析异常时通过 error() 获取应回应的 HTTP 状态码
     */
    explicit Header_get(TCP::Base_Link &link, int timeout_ms = 0,
                        const Limits &limits = Limits{});

    /*
     *@brief 解析过程中是否出错
     *@return 0 表示正常;否则为应回应的 HTTP 状态码
     *        (400 请求畸形 / 408 超时 / 413 请求体过大 / 414 URI 过长 / 431 请求头过大)
     */
    int error() const noexcept {
        return error_status_;
    }

    /*
     *@brief 获取请求头(大小写不敏感)
     */
    std::string get(const std::string &key, const std::string &def = "") const;
    bool has(const std::string &key) const;
    /*
     *@brief 获取 Cookie 值(Cookie 名区分大小写)
     */
    std::string cookie(const std::string &name, const std::string &def = "") const;
    bool has_cookie(const std::string &name) const;
    /*
     *@brief 是否为 WebSocket 升级请求
     *@note  要求方法是 GET,且 Upgrade 头含 websocket token、
     *       Connection 头含 upgrade token;两个头都按逗号分隔的
     *       token 列表解析(例如 "h2c, websocket" 也算)
     */
    bool is_websocket() const;
    /*
    *@brief 是否希望保持长连接
    *@note  HTTP/1.1 默认保持,Connection 含 close token 时关闭;
    *       HTTP/1.0 只有显式声明 keep-alive token 才保持
    */
    bool keep_alive() const;
};

// ==================== 当前请求上下文 ====================

namespace detail
{
/*
 *@brief 当前线程正在处理的请求(无则为 nullptr)
 *@note  Distributor 在调用处理器前设置,使 Header_send 能自动完成
 *       与请求相关的处理:HEAD 请求不发送响应体、按客户端意愿决定
 *       Connection 头等。处理器在其它线程发送响应时读到 nullptr,
 *       此时按 HTTP/1.1 的默认语义处理
 */
const Header_get *current_request() noexcept;
void set_current_request(const Header_get *request) noexcept;

/*
 *@brief 当前线程是否允许连接复用(Distributor::set_keep_alive 的线程内副本)
 */
bool reuse_allowed() noexcept;
void set_reuse_allowed(bool enable) noexcept;
}

// ==================== 响应 ====================

/*
 *@struct Cookie
 *@brief 响应端 Set-Cookie 结构体(名称/值 + 常用属性)
 */
struct Cookie
{
    std::string name;       ///< Cookie 名
    std::string value;      ///< Cookie 值
    std::string path;       ///< Path 属性,空表示不输出
    std::string domain;     ///< Domain 属性,空表示不输出
    std::string expires;    ///< Expires 属性(已是 HTTP 日期字符串)
    long max_age = -1;      ///< Max-Age(秒),<0 表示不输出
    bool secure = false;    ///< 是否仅 HTTPS 传输
    bool http_only = false; ///< 是否禁止脚本访问(防 XSS)
    std::string same_site;  ///< "Strict"/"Lax"/"None",空表示不输出

    Cookie() = default;
    Cookie(std::string name, std::string value)
        : name(std::move(name)), value(std::move(value)) {}

    /*
     *@brief 序列化为 Set-Cookie 头的值(不含 "Set-Cookie: " 前缀)
     */
    std::string to_string() const;

    // -------- 链式设置,便于书写 --------
    Cookie &set_path(const std::string &p)
    {
        path = p;
        return *this;
    }
    Cookie &set_domain(const std::string &d)
    {
        domain = d;
        return *this;
    }
    Cookie &set_max_age(long s)
    {
        max_age = s;
        return *this;
    }
    Cookie &set_secure(bool v = true)
    {
        secure = v;
        return *this;
    }
    Cookie &set_http_only(bool v = true)
    {
        http_only = v;
        return *this;
    }
    Cookie &set_same_site(const std::string &v)
    {
        same_site = v;
        return *this;
    }
};

/*
*@struct Header_send
*@brief HTTP响应结构体(状态行 + 响应头 + 响应体)
*
*       支持两种发送方式:
*         ① 一次性发送(默认):body 全部就绪后调用 send(),
*            框架自动补 Content-Length;
*         ② 流式发送:body 未知长度或边生成边发送(SSE、大文件下载、
*            实时日志推送等),把 streaming 置为 true(或使用 Stream /
*            EventStream / Download 构造),然后依次调用
*            send_head / send_chunk ... / end_stream。
*            此时若客户端支持 HTTP/1.1 且未指定 Content-Length,
*            框架自动使用 Transfer-Encoding: chunked;否则改用
*            "连接关闭"来定界响应体(强制 Connection: close)。
*
*       典型用法(流式升级为 chunked):
*         auto res = HTTP::Header_send::EventStream();
*         res.send_head(link);
*         for (...) res.send_chunk(link, "data: ...\n\n");
*         res.end_stream(link);
*
*       也可用 send_stream() 一步完成:
*         res.send_stream(link, [](std::string &chunk) -> bool { ... });
*/
struct Header_send
{
    int status = 200;                           ///< 状态码
    std::string status_text;                    ///< 自定义原因短语(为空则自动生成)
    std::string version = "HTTP/1.1";           ///< HTTP 版本
    std::map<std::string, std::string> headers; ///< 响应头
    std::string body;                           ///< 响应体(流式时作为首段数据)
    /*
     *@brief 是否保持长连接
     *@note  默认由 keep_alive_auto 自动决定;显式置为 false 且把
     *       keep_alive_auto 设为 false 时,响应头一律输出 Connection: close
     */
    bool keep_alive = false;
    /*
     *@brief 是否自动决定连接复用(默认开启)
     *@note  开启时:客户端允许复用 + Distributor 启用了 Keep-Alive +
     *       响应体可定界 时输出 Connection: keep-alive,否则输出 close
     */
    bool keep_alive_auto = true;
    std::vector<std::string> set_cookies;       ///< Set-Cookie 头(可多条,已格式化)

    /*
     *@brief 是否流式发送响应体(长度未知,边生成边发送)
     *@note  为 false 时走一次性发送(send()),框架自动补 Content-Length;
     *       首次调用 send_head/send_chunk 时会自动置为 true,
     *       避免出现"头里写了 Content-Length 却又追加数据"的畸形响应
     */
    mutable bool streaming = false;
    /*
    *@brief 流式发送时是否优先使用分块编码(Transfer-Encoding: chunked)
    *@note  仅在 streaming 为 true、用户未显式设置 Content-Length /
    *       Transfer-Encoding,且请求方不是 HTTP/1.0 时生效
    */
    bool use_chunked = true;

    mutable bool head_sent_ = false;    ///< 响应头是否已发出(流式内部状态)
    mutable size_t streamed_bytes_ = 0; ///< 已发出的流式字节数(不含分块封装)

    Header_send() = default;
    Header_send(int status, std::string body,
                const std::string &content_type = "text/plain; charset=utf-8");


    void set_header(const std::string &key, const std::string &value);
    /*
     *@brief 添加一条 Set-Cookie 头(Cookie 结构体)
     */
    void add_cookie(const Cookie &cookie);
    /*
     *@brief 添加一条 Set-Cookie 头(直接给已格式化的原始值)
     */
    void add_cookie(const std::string &raw_set_cookie);
    /*
     *@brief 删除一个 Cookie(输出 Max-Age=0 且 Expires 为过去时间)
     */
    void delete_cookie(const std::string &name, const std::string &path = "/");
    /*
    *@brief 序列化为可直接发送的字节流(状态行 + 响应头 +
    *       非流式时为完整报文;流式时只含头部与 body,分块封装由
    *       send_chunk 负责,一般不建议对流式响应调用本函数)
    */
    std::string serialize() const;
    /*
     *@brief 只序列化状态行 + 响应头(不含响应体)
     *@note  流式发送时自动决定定界方式:
     *       分块(补 Transfer-Encoding: chunked) /
     *       定长(沿用用户设置的 Content-Length) /
     *       关闭连接定界(强制 Connection: close)
     */
    std::string serialize_head() const;
    /*
     *@brief 发送该响应
     *@note  非流式:一次性发出头部与 body;
     *       流式:等价于 send_head + body(作为首段) + end_stream
     */
    void send(TCP::Base_Link &link) const;

    // -------- 流式发送 --------

    /*
     *@brief 是否以分块传输编码(Transfer-Encoding: chunked)发送响应体
     */
    bool is_chunked() const;
    /*
     *@brief 是否以"连接关闭"定界响应体(既不分块也没有 Content-Length)
     */
    bool is_close_delimited() const;
    /*
     *@brief 响应头是否已发出
     */
    bool head_sent() const noexcept {
        return head_sent_;
    }
    /*
     *@brief 已发出的流式响应体字节数(不含分块封装)
     */
    size_t streamed_bytes() const noexcept {
        return streamed_bytes_;
    }
    /*
    *@brief 是否存在指定响应头(名称大小写不敏感)
    */
    bool has_header(const std::string &key) const;
    /*
     *@brief 当前响应是否对应 HEAD 请求
     *@note  依据 Distributor 设置的当前请求上下文判断;ctx 为空时返回 false
     */
    bool is_head_request() const;
    /*
     *@brief 是否应抑制响应体
     *@note  HEAD 请求、1xx/204/304 状态码均不应有响应体;
     *       抑制时 Content-Length 仍按 body.size() 计算(HEAD 语义)
     */
    bool body_suppressed() const;
    /*
     *@brief 响应头是否会声明连接可复用
     *@note  该结果同时影响 Connection 头的取值与访问日志
     */
    bool will_reuse_connection() const;

    /*
     *@brief 发送响应头(流式发送的第一步,也是开始发送的时刻)
     *@return true 表示头部已写出且连接仍可用
     *@note  重复调用不会重复发送
     */
    bool send_head(TCP::Base_Link &link) const;
    /*
     *@brief 发送一段流式数据(首次调用会自动先发响应头)
     *@param data 数据;分块模式下自动加"长度行 + CRLF"封装
     *@param len  数据长度;为 0 表示无数据(空块会被当作结束标记,直接跳过)
     *@return true 表示已写出且连接仍可用;false 表示连接已不可用
     */
    bool send_chunk(TCP::Base_Link &link, const char *data, size_t len) const;
    bool send_chunk(TCP::Base_Link &link, const std::string &data) const;
    bool send_chunk(TCP::Base_Link &link, const std::vector<char> &data) const;
    /*
     *@brief 结束流式响应(分块模式补发结束块 0\r\n\r\n),并输出响应日志
     *@return true 表示收尾成功
     */
    bool end_stream(TCP::Base_Link &link) const;
    /*
     *@brief 用生产者回调一次性完成流式响应(自动发头、分块、收尾)
     *@param producer 生产者:填充 chunk 作为下一段数据;
     *                返回 true 表示还有数据,false 表示数据结束
     *@return true 表示整段响应已完整写出;false 表示中途失败(应关闭连接)
     *@note  生产者抛异常视为流中断,此时不会补发结束块,
     *       以免对端把截断的数据当成完整响应
     */
    bool send_stream(TCP::Base_Link &link,
                     const std::function<bool(std::string &chunk)> &producer) const;
    /*
     *@brief 开始流式响应(send_head 的语义化别名)
     */
    bool begin_stream(TCP::Base_Link &link) const {
        return send_head(link);
    }

    // -------- 便捷构造 --------
    static Header_send Text(const std::string &body, int status = 200);
    static Header_send Html(const std::string &body, int status = 200);
    static Header_send Json(const std::string &body, int status = 200);
    static Header_send Status(int status, const std::string &message = "");
    static Header_send Redirect(const std::string &location, int status = 302);
    /*
     *@brief 构造长度未知的流式响应(默认使用分块编码)
     */
    static Header_send Stream(const std::string &content_type =
                                  "application/octet-stream",
                              int status = 200);
    /*
     *@brief 构造 Server-Sent Events 流式响应(长连接,关闭代理缓冲)
     */
    static Header_send EventStream(int status = 200);
    /*
     *@brief 构造已知总长度的流式下载响应(定长流式,不分块)
     *@param content_type 媒体类型
     *@param total_size   响应体总字节数(必须与实际发送量一致)
     *@param filename     非空时输出 Content-Disposition 附件头
     */
    static Header_send Download(const std::string &content_type,
                                unsigned long long total_size,
                                const std::string &filename = "");
};

// ==================== 请求类型 ====================

/*
 *@enum RequestType
 *@brief 请求类别:框架据此决定调用 Router 的哪个处理入口
 *@note  需要支持新的自定义协议时,可在此枚举中扩充取值,
 *       并配合 Router::supports / Router::handle_custom 使用
 */
enum class RequestType
{
    Http,      ///< 普通 HTTP 请求
    WebSocket, ///< WebSocket 升级请求
    Custom     ///< 其它自定义请求
};

// ==================== 路由处理器 ====================

/*
 *@class Router
 *@brief 请求路由处理器接口类。一个 Router 对应路由表中的一条路径,
 *       同一路径可按请求类型注册多个 Router(见 Distributor),
 *       每个 Router 可以处理一种或多种请求类型:
 *         - 普通 HTTP 请求:重写 handle_request(默认即支持)
 *         - WebSocket 请求:重写 supports 让 WebSocket 返回 true,
 *           并重写 handle_websocket
 *         - 自定义请求:重写 supports 让 Custom 返回 true,
 *           并重写 handle_custom
 *
 *       同一个 Router 也可以同时处理多种类型,例如一个聊天室 Router:
 *         GET /chat  -> handle_request   (查询在线人数等)
 *         WS  /chat  -> handle_websocket (实时消息)
 */
class Router
{
public:
    Router() = default;
    virtual ~Router() = default;

    /*
     *@brief 该 Router 是否处理指定类型的请求
     *@note  默认仅处理普通 HTTP 请求
     */
    virtual bool supports(RequestType type) const
    {
        return type == RequestType::Http;
    }

    /*
     *@brief 处理普通 HTTP 请求
     */
    virtual void handle_request(TCP::Base_Link &link, const Header_get &header)
    {
        (void)link;
        (void)header;
    }

    /*
     *@brief 处理 WebSocket 连接(握手成功后由框架回调)
     *@param ws 已建立连接的 WebSocket 对象,可在其中收发消息
     */
    virtual void handle_websocket(WebSocket &ws, const Header_get &header)
    {
        (void)ws;
        (void)header;
    }

    /*
     *@brief 处理自定义请求
     *@return true 表示请求已被处理
     */
    virtual bool handle_custom(TCP::Base_Link &link, const Header_get &header)
    {
        (void)link;
        (void)header;
        return false;
    }
};

// ==================== 请求检查(拦截) ====================

/*
 *@enum FilterAction
 *@brief 过滤器对请求的处理结果
 */
enum class FilterAction
{
    Continue, ///< 放行:继续执行后续过滤器与路由
    Block,    ///< 拦截:立即用 response 回应客户端,并关闭连接
    Close     ///< 断开:不发送任何响应,直接关闭连接(安全脚本 return -1)
};

/*
 *@class RequestFilter
 *@brief 请求过滤器(中间件)接口。在路由匹配之前逐个执行,
 *       适合做 IP 黑名单、路径/UA 校验、限流、鉴权等恶意请求拦截。
 *
 *       过滤器可以: ① 只读检查;② 拦截并返回自定义响应;
 *       ③ 修改 request(如规范化 url、去除/补充头部)后放行,
 *          修改会直接影响后续过滤器与路由匹配。
 *
 *       典型用法:继承本类并重写 inspect;或用 Distributor::add_filter
 *       直接注册 lambda。
 */
class RequestFilter
{
public:
    virtual ~RequestFilter() = default;

    /*
     *@brief 检查一个已解析的请求
     *@param request  已解析的请求(可读可改)
     *@param link     当前连接(可用 get_ip() 获取客户端地址)
     *@param response 若返回 Block,则把要发送的响应写到这里(Close 时忽略)
     *@return FilterAction::Continue 放行; Block 拦截; Close 直接断开(不发响应)
     */
    virtual FilterAction inspect(Header_get &request, TCP::Base_Link &link,
                                 Header_send &response) = 0;
};

// ==================== 分发器 ====================

/*
 *@class Distributor
 *@brief 连接请求处理分发器:接受连接,按"域名 + 路径 + 请求类型"匹配路由,
 *       再按照请求类型(HTTP / WebSocket / 自定义)分发给对应的处理入口。
 *       每个连接在独立线程中处理。
 *
 *       路由模型:一条路由 = 路径 + 请求类型。同一条路径可以同时注册 HTTP
 *       处理器(add_router)与 WebSocket 处理器(add_websocket_router),
 *       两者存放在各自的槽位里互不覆盖;一次请求的分发顺序是:
 *         ① 选域名表(精确域名 -> 后缀最长的通配子域 -> 默认表);
 *         ② 在表内匹配路径(精确优先 -> 最长前缀);
 *         ③ 按请求类型取处理器;该路径没有当前类型的处理器时交给
 *            兜底处理器(set_not_found_router),再没有则返回 404。
 *       WebSocket 的回退顺序为:路由 -> 兜底处理器 -> 全局处理器 -> 404。
 */
class Distributor
{
public:
    /// WebSocket 处理器:当升级握手成功后回调,用户在其中收发消息
    using WsHandler = std::function<void(WebSocket &, const Header_get &)>;

    /*
     *@brief 请求类型判定器:根据已解析的请求返回其类型
     */
    using TypeClassifier = std::function<RequestType(const Header_get &)>;

    Distributor() = default;
    explicit Distributor(TCP::Server &server);
    ~Distributor();

    Distributor(const Distributor &) = delete;
    Distributor(Distributor &&) noexcept = delete;
    Distributor &operator=(const Distributor &) = delete;
    Distributor &operator=(Distributor &&) noexcept = delete;

    /*
     *@brief 添加路由处理器
     *@warning 请在调用 start() 之前添加路由处理器
     *@param path 路由路径。空串等价于 "/";缺少开头的 '/' 会自动补上,
     *            并输出告警。以 '/' 结尾(含 "/")的路径按前缀匹配,
     *            其它路径与请求的 url 精确匹配;两者同时命中时取更精确的一条
     *@param router 路由处理器对象(null 会被忽略并告警)
     *@note  该重载注册到"默认"域名表,对任意 Host 生效(向后兼容);
     *       它写入的是"通用处理器"槽位,不覆盖同一路径由
     *       add_websocket_router 注册的 WebSocket 处理器。
     *       同一路径重复调用本函数时,后注册的处理器替换先注册的,
     *       并输出一条告警(避免配置写重了却毫无察觉)
     */
    void add_router(const std::string &path, std::shared_ptr<Router> router);

    /*
     *@brief 为指定域名添加路由处理器(域名路由/虚拟主机)
     *@param host 域名,大小写不敏感,可带端口(端口会被忽略),
     *            也接受完整 Host 值(例如 example.com:8080)。
     *            支持精确域名(example.com)与通配子域(*.example.com);
     *            多个通配模式同时命中时取"后缀最长(最具体)"的一条
     *@param path 路由路径(匹配规则同上一个重载)
     *@param router 路由处理器对象
     *@note  一旦某个 Host 命中了专属域名表,就不再回退到默认表;
     *       未命中任何域名表时才使用默认表。请求的兜底处理器同样按域名表选择。
     *       host 为空等价于注册到默认域名表(与单参数重载一致)
     */
    void add_router(const std::string &host, const std::string &path,
                    std::shared_ptr<Router> router);

    /*
     *@brief 规范化域名:转小写、去掉端口、去掉结尾的点
     *@param host 原始 Host(可为空)
     *@return 规范化后的域名
     */
    static std::string normalize_host(const std::string &host);

    /*
     *@brief 为指定路径注册 WebSocket 处理器
     *@param path 路由路径(匹配规则与 add_router 相同)
     *@param handler 握手成功后的回调(null 会被忽略并告警)
     *@note  处理器写入该路径的"WebSocket 专用槽位",因此同一路径可以同时
     *       拥有 HTTP 处理器与 WebSocket 处理器,两者互不覆盖;
     *       WebSocket 请求优先使用专用槽位,没有时才回退到通用处理器。
     *       同一路径重复调用本函数时,后注册的替换先注册的并输出告警
     */
    void add_websocket_router(const std::string &path, WsHandler handler);

    /*
     *@brief 为指定域名注册 WebSocket 处理器(域名路由)
     *@param host 域名(规则同 add_router 的域名重载)
     *@param path 路由路径
     *@param handler 握手成功后的回调
     */
    void add_websocket_router(const std::string &host, const std::string &path,
                              WsHandler handler);

    /*
     *@brief 设置未匹配到路由时的处理器(默认返回 404)
     *@note  兜底处理器按请求类型使用:Http 请求调用 handle_request,
     *       WebSocket 请求调用 handle_websocket,Custom 请求调用 handle_custom;
     *       但只有 supports(该类型) 为 true 时才会交给它,否则按 404 处理。
     *       因此一个只处理 WebSocket 的兜底处理器不会影响普通 HTTP 请求
     */
    void set_not_found_router(std::shared_ptr<Router> router);

    /*
     *@brief 为指定域名设置未匹配处理器
     *@param host 域名(规则同 add_router 的域名重载)
     *@note  该域名没有配置任何路由时,这也会创建一张空的域名专属表:
     *       此后该域名的请求不再落到默认表(与 add_router 的域名语义一致);
     *       host 为空等价于设置默认表的兜底处理器
     */
    void set_not_found_router(const std::string &host, std::shared_ptr<Router> router);
    /*
     *@brief 设置全局 WebSocket 处理器(向后兼容)
     *@note  回退顺序:路径命中的 WebSocket 处理器 -> 兜底处理器(若支持 WebSocket)
     *       -> 本全局处理器 -> 404。
     *       需要按路径区分多个 WebSocket 时请使用 add_websocket_router
     */
    void set_websocket_handler(WsHandler handler);
    /*
     *@brief 设置请求类型判定器
     *@note  不设置时使用默认判定:WebSocket 升级请求 -> WebSocket,
     *       其余 -> Http。需要支持自定义请求时可通过它返回 Custom
     */
    void set_type_classifier(TypeClassifier classifier);

    /*
     *@brief 设置单次请求读取的总超时(毫秒)
     *@param ms 0 表示不限制(不推荐,易受 Slowloris 攻击),默认 30000
     */
    void set_read_timeout_ms(int ms);
    /*
     *@brief 设置请求解析的资源上限(见 Limits)
     */
    void set_limits(const Limits &limits);
    /*
    *@brief 是否启用 HTTP Keep-Alive(连接复用),默认关闭
    *@note  启用后,当请求允许保持连接、响应体可定界时,框架会在同一连接上
    *       继续处理下一个请求,响应头自动输出 Connection: keep-alive;
    *       关闭时响应头输出 Connection: close,客户端会主动断开连接。
    *       无需处理器手动设置 Header_send::keep_alive
    */
    void set_keep_alive(bool enable);

    /*
     *@brief 启用 TLS(HTTPS / WSS)
     *@param ctx 由 TLS::make_server_context 创建的服务端上下文;
     *           传 nullptr 表示关闭 TLS(恢复明文)
     *@param handshake_timeout_ms TLS 握手总超时(毫秒),0 表示不限制
     *@warning 请在调用 start() 之前设置。启用后每条新连接先在工作线程中
     *         完成 TLS 握手,失败的连接被丢弃;握手不再阻塞 accept
     */
    void set_tls(std::shared_ptr<TLS::Context> ctx, int handshake_timeout_ms = 10000);
    /*
     *@brief 是否已启用 TLS
     */
    bool tls_enabled() const noexcept;

    /// 过滤器函数式形式:便于直接用 lambda 注册请求检查器
    using FilterFunc =
        std::function<FilterAction(Header_get &, TCP::Base_Link &, Header_send &)>;

    /*
     *@brief 注册一个请求过滤器(中间件)
     *@param filter 过滤器对象
     *@warning 请在调用 start() 之前注册
              *@note  多个过滤器按注册顺序依次执行;任一过滤器返回 Block
     *       则立即停止后续流程,用其 response 回应并关闭连接;
     *       返回 Close 则不发任何响应直接断开
     */
    void add_filter(std::shared_ptr<RequestFilter> filter);

    /*
     *@brief 注册一个请求过滤器(lambda/std::function 便捷形式)
     */
    void add_filter(FilterFunc filter);

    /*
     *@brief 清空所有已注册的请求过滤器
     */
    void clear_filters();

    /*
     *@brief 启动分发器,在后台线程中接受连接
     */
    void start();
    /*
     *@brief 停止分发器,关闭监听与所有活动连接,并等待处理线程结束
     */
    void stop();
    /*
     *@brief 是否正在运行
     */
    bool running() const noexcept;

private:
    struct Worker
    {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done; // 线程是否已结束
    };

    void accept_loop();
    void handle_connection(std::shared_ptr<TCP::Base_Link> link);
    /*
     *@brief 若已启用 TLS,则在连接上完成服务端握手并升级该连接
     *@return true 表示可以继续处理(未启用 TLS 或握手成功);
     *        false 表示握手失败,连接应被丢弃
     */
    bool establish_tls(TCP::Base_Link &link);

    /*
     *@brief 当前活动连接数(含本连接)，仅用于访问日志
     */
    size_t active_clients();

    /*
     *@brief 一条路径上的处理器槽位
     *@note  通用处理器与 WebSocket 专用处理器分开存放:
     *       add_router 写 router,add_websocket_router 写 websocket,
     *       两者互不覆盖,因此同一路径可以同时服务 HTTP 与 WebSocket
     */
    struct Route_entry
    {
        std::shared_ptr<Router> router;    ///< 通用处理器(add_router 注册)
        std::shared_ptr<Router> websocket; ///< WebSocket 专用处理器(add_websocket_router 注册)

        /*
         *@brief 取出能处理指定请求类型的处理器
         *@return 空表示该路径没有该类型的处理器(交由兜底处理器 / 404)
         *@note  WebSocket 优先用专用处理器,其次才看通用处理器是否 supports();
         *       其它类型只认通用处理器,且必须 supports() 返回 true
         */
        std::shared_ptr<Router> pick(RequestType type) const
        {
            if (type == RequestType::WebSocket && websocket)
                return websocket;
            if (router && router->supports(type))
                return router;
            return nullptr;
        }
    };

    /* 一个域名对应一张路由表 */
    struct HostTable
    {
        std::map<std::string, Route_entry> routers; ///< path -> 处理器槽位
        std::shared_ptr<Router> not_found;          ///< 该域名的兜底处理器
    };

    /*
     *@brief 一次路由匹配的结果
     *@note  router 已按本次请求的类型过滤(非空即代表 supports() 为 true);
     *       path / host_table / path_matched 只用于访问日志与排障
     */
    struct RouteMatch
    {
        std::shared_ptr<Router> router;    ///< 命中的处理器;空表示未命中
        std::shared_ptr<Router> not_found; ///< 该域名表对应的兜底处理器
        std::string path;                  ///< 命中的路由路径(日志用)
        bool host_table = false;           ///< 是否命中域名专属表(日志用)
        bool path_matched = false;         ///< 路径命中但没有该类型的处理器(日志用)
    };

    /*
     *@brief 注册 / 替换一条路径的处理器
     *@param table     目标路由表
     *@param path      路由路径(空串 -> "/";缺少开头 '/' 时自动补上并告警)
     *@param router    处理器;为空会被忽略并告警
     *@param websocket true 写入 WebSocket 专用槽位,false 写入通用槽位
     *@note  只替换同一槽位:通用处理器不会覆盖 WebSocket 处理器,反之亦然
     */
    void register_route(std::map<std::string, Route_entry> &table, const std::string &path,
                        std::shared_ptr<Router> router, bool websocket);

    /*
     *@brief 查找域名对应的专属路由表
     *@param host 已规范化的域名
     *@return 命中的表;返回 nullptr 表示使用默认表
     *@note  先精确匹配;多个通配子域(*.example.com)同时命中时,
     *       取后缀最长(最具体)的一条,与配置书写顺序无关
     */
    const HostTable *find_host_table(const std::string &host) const;

    /*
     *@brief 在一张路由表内按路径查找:精确匹配优先,其次最长前缀
     *@param routers 路由表
     *@param url     已解码的请求路径
     *@param path    命中时写入命中的路由路径(可为 nullptr)
     *@return 命中的路径条目;nullptr 表示没有路径命中
     *@note  这里只看路径,不看请求类型;类型选择由 Route_entry::pick 完成
     */
    const Route_entry *find_route(const std::map<std::string, Route_entry> &routers,
                                  const std::string &url, std::string *path) const;

    /*
     *@brief 按"域名 + URL + 请求类型"匹配路由
     *@param host 已规范化的域名
     *@param url  已解码的请求路径
     *@param type 请求类型
     *@note  先选域名表(无则用默认表),再在其中做精确 / 最长前缀匹配,
     *       最后按请求类型取出处理器;路径命中但类型不匹配时
     *       router 为空、path_matched 为 true,由兜底处理器接管
     */
    RouteMatch match_route(const std::string &host, const std::string &url,
                           RequestType type) const;

    /*
     *@brief 依次执行所有请求过滤器
     *@return 首个返回非 Continue 的过滤器的结果;全部放行则返回 Continue
     *@note  过滤器抛出异常时按"拒绝"处理(fail-closed),回应 500
     */
    FilterAction run_filters(Header_get &request, TCP::Base_Link &link,
                             Header_send &response);

    /*
     *@brief 各请求类型的处理入口
     *@return 是否允许在本连接上继续处理下一个请求(Keep-Alive)
     */
    bool dispatch_http(std::shared_ptr<TCP::Base_Link> &link, const Header_get &request,
                       const RouteMatch &match);
    bool dispatch_websocket(std::shared_ptr<TCP::Base_Link> &link, const Header_get &request,
                            const RouteMatch &match);
    bool dispatch_custom(std::shared_ptr<TCP::Base_Link> &link, const Header_get &request,
                         const RouteMatch &match);

    /*
     *@brief 发送响应后优雅关闭连接:先半关闭写方向并排空对端剩余数据,
     *       避免未读数据触发 RST 冲掉已发出的响应(如 413/414/431)
     */
    void send_and_close(TCP::Base_Link &link, Header_send response);

    TCP::Server *server_ = nullptr;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;

    std::mutex workers_mtx_;
    std::vector<Worker> workers_;

    std::mutex clients_mtx_;
    std::map<size_t, std::shared_ptr<TCP::Base_Link>> clients_;
    std::atomic<size_t> next_client_id_{0};

    std::map<std::string, Route_entry> routers_; // 默认域名表:匹配任意 Host
    std::shared_ptr<Router> not_found_;          // 默认域名的未匹配处理器
    std::map<std::string, HostTable> hosts_;     // 域名(已规范化)-> 专属路由表
    std::vector<std::shared_ptr<RequestFilter>> filters_;    // 请求检查器(按注册顺序执行)
    WsHandler ws_handler_;                                   // 全局 WebSocket 处理器(回退)
    TypeClassifier type_classifier_;                         // 请求类型判定器

    int read_timeout_ms_ = 30000;     // 单次请求读取的总超时(毫秒),0 表示不限制
    bool keep_alive_enabled_ = false; // 是否启用 HTTP Keep-Alive(连接复用)
    Limits limits_{};                 // 请求解析资源上限
    std::shared_ptr<TLS::Context> tls_ctx_;   // 非空表示启用 TLS(HTTPS/WSS)
    int tls_handshake_timeout_ms_ = 10000;    // TLS 握手总超时(毫秒)
};
}
#endif // HTTP_H