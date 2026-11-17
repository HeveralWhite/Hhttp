#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#elif defined(__linux__)
#include <unistd.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

#include "HTTP.h"
#include "JS.h"
#include "Log.h"
#include "TCP.h"
#include "TLS.h"
#include <nlohmann/json.hpp>

/*
 * 示例入口:端口、域名、路由、脚本与脚本的文件访问权限全部由 JSON 配置文件给出。
 *
 * 配置文件结构(见 "配置文件示例.json"):
 *   base_msg       : HTTP_port / HTTPS_port / pfx_path / pfx_password
 *                    (可选: certificates / script_dir / file_max_size /
 *                     js_memory_limit / js_security_memory_limit /
 *                     js_global_memory_limit,单位字节,0 表示不限制)
 *                    (可选: colorful_log,是否输出彩色日志,默认 true)
 *                    (可选: js_security_script / js_global_script,
 *                     写法见下面的"脚本入口")
 *   roter          : [ { "域名/路径": { "http": {...}, "websocket": {...} }, ... }, ... ]
 *   undefine_roter : 未匹配到路径时使用的处理器(结构同 http / websocket)
 * 每个处理器包含:
 *   js_path        : JS 脚本路径(相对 --dir,也可写绝对路径;留空表示该类型不处理)
 *   js_read_rule   : 允许读取的目录列表(',' 或 ';' 分隔,相对 --dir;留空表示禁止读)
 *   js_write_rule  : 允许写入的目录列表(同上;留空表示禁止写)
 *   js_sql_read_rule / js_sql_write_rule : 允许打开的 sqlite 库(同上,可通配)
 *   js_full_access : 完全文件 / SQLite 访问(高危,默认 false)
 *
 * 脚本入口(base_msg.js_security_script / base_msg.js_global_script)有两种写法:
 *   1) 字符串:只有脚本路径;安全检测脚本没有任何文件 / SQL 权限,
 *      全局数据脚本沿用旧版本行为(完全文件 / SQL 权限);
 *   2) 对象  :与 roter 处理器完全一致,按上面的 js_* 字段单独授予权限。
 *
 * 路由键写法:
 *   "域名/路径"       -> 只对该域名生效
 *   "/路径"           -> 默认域名表,对任意 Host 生效(仅在没有同名域名专属表时使用)
 *   "*.abc.com/路径"  -> 通配子域
 *   路径以 / 结尾(或结尾写 * / **)表示前缀匹配
 *   同一路径可以同时写 http 与 websocket 两个处理器,互不覆盖
 */

namespace
{

using json = nlohmann::json;

/* ==================== 配置文件结构 ==================== */

/*
 *@struct Script_config
 *@brief 一个处理入口(HTTP 或 WebSocket)对应的脚本及文件访问权限
 */
struct Script_config
{
    std::string js_path;                  ///< 脚本文件路径(配置文件原样给出的写法)
    std::vector<std::string> read_dirs;   ///< 允许读取的目录(相对脚本目录 --dir)
    std::vector<std::string> write_dirs;  ///< 允许写入的目录(相对脚本目录 --dir)
    std::vector<std::string> sql_read_dbs;///< 允许只读打开的数据库(路径模式)
    std::vector<std::string> sql_write_dbs;///< 允许读写的数据库(路径模式)
    bool full_access = false;             ///< 是否开放文件系统 / SQL 全部权限(默认关闭)

    /*
     *@brief 是否配置了脚本(未配置表示该类型不处理)
     */
    bool enabled() const noexcept
    {
        return !js_path.empty();
    }
};

/*
 *@struct Route_config
 *@brief 一条路由:域名 + 路径 + HTTP / WebSocket 脚本
 */
struct Route_config
{
    std::string host;        ///< 域名(空表示默认域名表)
    std::string path;        ///< 路径(以 / 结尾表示前缀匹配)
    Script_config http;      ///< HTTP 处理器
    Script_config websocket; ///< WebSocket 处理器

    /*
     *@brief 至少配置了一个脚本才算有效路由
     */
    bool enabled() const noexcept
    {
        return http.enabled() || websocket.enabled();
    }
};

/*
 *@struct Certificate_config
 *@brief 一张 HTTPS 证书的配置(PFX/P12 文件,或 PEM 证书链 + 私钥)
 */
struct Certificate_config
{
    std::string pfx_path;     ///< PFX/P12 证书路径
    std::string pfx_password; ///< PFX 密码(无密码留空)
    std::string cert_file;    ///< PEM 证书链(与 key_file 一起使用)
    std::string key_file;     ///< PEM 私钥
};

/*
 *@struct App_config
 *@brief 整个配置文件解析后的结果
 */
struct App_config
{
    int http_port = 0;                              ///< HTTP 监听端口(0 表示不监听)
    int https_port = 0;                             ///< HTTPS 监听端口(0 表示不监听)
    std::string pfx_path;                           ///< PFX/P12 证书路径(单证书写法)
    std::string pfx_password;                       ///< PFX 密码(单证书写法)
    std::string cert_file;                          ///< PEM 证书链(单证书写法)
    std::string key_file;                           ///< PEM 私钥(单证书写法)
    std::vector<Certificate_config> certificates;   ///< 多证书写法(按 SNI 选择;为空时用单证书字段)
    std::string script_dir = "scripts";             ///< 脚本目录(命令行 --dir 优先)
    std::size_t file_max_size = 8u * 1024u * 1024u; ///< 脚本单次读取上限
    int js_exec_timeout_ms = 0;                     ///< 脚本单次执行超时(0 表示不限制)
    int websocket_recv_timeout_ms = 0;              ///< ws.recv() 缺省超时(0 表示一直阻塞)
    std::size_t js_memory_limit = 64u * 1024u * 1024u;          ///< 业务脚本内存上限
    std::size_t js_security_memory_limit = 64u * 1024u * 1024u; ///< 安全脚本内存上限
    std::size_t js_global_memory_limit = 128u * 1024u * 1024u;  ///< 全局脚本内存上限
    bool colorful_log = true;                       ///< 彩色日志输出(某些平台终端不兼容 ANSI 时可关)
    Script_config security_script;                  ///< 安全检测脚本及其文件 / SQL 权限
    Script_config global_script;                    ///< 全局数据脚本及其文件 / SQL 权限
    std::vector<Route_config> routes;               ///< "roter" 里的路由表
    Route_config fallback;                          ///< "undefine_roter":未匹配路径时的处理器
    std::string source_path;                        ///< 配置文件实际路径
    std::string source_dir;                         ///< 配置文件所在目录
};

/* ==================== Router 实现 ==================== */

/*
 *@class ScriptRouter
 *@brief 用 JS 脚本实现的 Router:HTTP 请求走 JS_HTTP,WebSocket 走 JS_WS
 */
class ScriptRouter : public HTTP::Router
{
public:
    ScriptRouter(std::string http_script, std::string ws_script)
        : http_script_(std::move(http_script)), ws_script_(std::move(ws_script)) {}

    /*
     *@brief 按配置声明支持的类型(没配脚本的类型不支持)
     */
    bool supports(HTTP::RequestType type) const override
    {
        switch (type)
        {
        case HTTP::RequestType::Http:
            return !http_script_.empty();
        case HTTP::RequestType::WebSocket:
            return !ws_script_.empty();
        default:
            return false;
        }
    }

    /*
     *@brief 普通 HTTP 请求:构造 JS_HTTP 即完成"执行脚本 + 发送响应"
     */
    void handle_request(TCP::Base_Link &link, const HTTP::Header_get &header) override
    {
        if (http_script_.empty())
        {
            HTTP::Header_send::Status(404).send(link);
            return;
        }
        JS_HTTP handler(http_script_, link, header);
    }

    /*
     *@brief WebSocket 连接:构造 JS_WS 即完成"执行脚本 + 收发消息"
     */
    void handle_websocket(HTTP::WebSocket &ws, const HTTP::Header_get &header) override
    {
        if (ws_script_.empty())
        {
            // 握手已完成,这里只能记录日志;框架会在返回后关闭连接
            Log::warning("Hhttp: websocket route without script, connection closed");
            return;
        }
        JS_WS handler(ws_script_, ws, header);
    }

private:
    std::string http_script_; ///< HTTP 脚本路径(空表示不处理)
    std::string ws_script_;   ///< WebSocket 脚本路径(空表示不处理)
};

/* ==================== 通用小工具 ==================== */

/*
 *@brief 去掉首尾空白
 */
std::string trim(const std::string &text)
{
    const std::size_t begin = text.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos)
        return std::string();

    const std::size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(begin, end - begin + 1);
}

/*
 *@brief 转小写(域名 / 脚本路径规范化用)
 */
std::string to_lower_copy(std::string text)
{
    for (char &ch : text)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return text;
}

/*
 *@brief 拆分目录列表:',' 与 ';' 都是分隔符,忽略空项与首尾空白
 */
std::vector<std::string> split_dirs(const std::string &text)
{
    std::vector<std::string> out;
    std::string item;
    for (char ch : text)
    {
        if (ch != ',' && ch != ';')
        {
            item.push_back(ch);
            continue;
        }

        const std::string value = trim(item);
        if (!value.empty())
            out.push_back(value);
        item.clear();
    }

    const std::string value = trim(item);
    if (!value.empty())
        out.push_back(value);
    return out;
}

/*
 *@brief 取可执行文件所在目录(失败时返回空串)
 *@note  Windows 用 GetModuleFileNameA;Linux 读 /proc/self/exe;
 *       macOS 用 _NSGetExecutablePath。取不到时返回空串,调用方会退回
 *       "按当前工作目录解析"的行为。
 */
std::string exe_directory()
{
#if defined(_WIN32)
    char buffer[MAX_PATH] {};
    const DWORD len = ::GetModuleFileNameA(nullptr, buffer, MAX_PATH);
    if (len == 0 || len >= MAX_PATH)
        return std::string();
    const std::string path(buffer, len);
#elif defined(__linux__)
    char buffer[4096] = {0};
    const ssize_t len = ::readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (len <= 0)
        return std::string();
    const std::string path(buffer, static_cast<std::size_t>(len));
#elif defined(__APPLE__)
    char buffer[4096] = {0};
    uint32_t size = static_cast<uint32_t>(sizeof(buffer));
    if (_NSGetExecutablePath(buffer, &size) != 0)
        return std::string();
    const std::string path(buffer);
#else
    return std::string();
#endif

    const std::size_t pos = path.find_last_of("\\/");
    return (pos == std::string::npos) ? std::string() : path.substr(0, pos);
}

/*
 *@brief 路径是否存在(区分目录 / 普通文件)
 */
bool path_exists(const std::string &path, bool want_directory)
{
    std::error_code ec;
    const std::filesystem::path item = std::filesystem::u8path(path);
    return want_directory ? std::filesystem::is_directory(item, ec)
           : std::filesystem::is_regular_file(item, ec);
}

/*
 *@brief 解析输入路径(配置文件 / 脚本目录)
 *       相对路径在当前工作目录下找不到时,依次回退到
 *       "exe 所在目录" 与 "exe 所在目录的上一级",
 *       这样直接在 build/ 里运行 Hhttp.exe 也能找到源码根目录的 config.json / scripts
 */
std::string resolve_input_path(const std::string &path, bool want_directory)
{
    if (path.empty() || path_exists(path, want_directory))
        return path;

    const std::filesystem::path given = std::filesystem::u8path(path);
    if (given.is_absolute())
        return path;

    const std::string base = exe_directory();
    if (base.empty())
        return path;

    const std::filesystem::path candidates[] = {
        std::filesystem::path(base) / given,
        std::filesystem::path(base) / ".." / given,
    };
    for (const std::filesystem::path &item : candidates)
    {
        std::error_code ec;
        const bool found = want_directory ? std::filesystem::is_directory(item, ec)
                           : std::filesystem::is_regular_file(item, ec);
        if (found)
            return item.lexically_normal().u8string();
    }
    return path;
}

/* ==================== JSON 取值小工具 ==================== */

/*
 *@brief 读取字符串字段(缺省 / null 视为空串)
 */
bool read_text(const json &owner, const char *key, std::string &out, std::string &error)
{
    out.clear();
    const auto it = owner.find(key);
    if (it == owner.end() || it->is_null())
        return true;

    if (!it->is_string())
    {
        error = std::string(key) + ": expected a string";
        return false;
    }
    out = trim(it->get<std::string>());
    return true;
}

/*
 *@brief 读取布尔字段(允许 true/false、1/0 或 "true"/"false" 等写法,缺省为 false)
 */
bool read_bool(const json &owner, const char *key, bool &out, std::string &error)
{
    out = false;
    const auto it = owner.find(key);
    if (it == owner.end() || it->is_null())
        return true;

    if (it->is_boolean())
    {
        out = it->get<bool>();
        return true;
    }
    if (it->is_number_integer())
    {
        out = it->get<int>() != 0;
        return true;
    }
    if (it->is_string())
    {
        const std::string text = to_lower_copy(trim(it->get<std::string>()));
        if (text == "true" || text == "1" || text == "yes" || text == "on")
        {
            out = true;
            return true;
        }
        if (text.empty() || text == "false" || text == "0" || text == "no" || text == "off")
        {
            out = false;
            return true;
        }
    }

    error = std::string(key) + ": expected a boolean";
    return false;
}

/*
 *@brief 读取布尔字段(缺省 / null 时保持 out 原值)
 *@note  给"默认开启"的开关用:read_bool 在缺省时会把 out 置 false,
 *       直接用会破坏默认值
 */
bool read_bool_keep(const json &owner, const char *key, bool &out, std::string &error)
{
    const auto it = owner.find(key);
    if (it == owner.end() || it->is_null())
        return true;
    return read_bool(owner, key, out, error);
}

/*
 *@brief 读取端口等整数字段(允许整数或数字字符串,缺省 / 空串视为 0)
 *@note  直接 get<int>() 在数值超范围时会抛 json::out_of_range(派生自
 *       std::exception),配置文件写错一个数字就会让进程在启动阶段崩溃;
 *       这里先取到大整数类型再自行做范围检查,越界只报配置错误。
 */
bool read_int(const json &owner, const char *key, int &out, std::string &error)
{
    out = 0;
    const auto it = owner.find(key);
    if (it == owner.end() || it->is_null())
        return true;

    if (it->is_number_unsigned())
    {
        const unsigned long long raw = it->get<unsigned long long>();
        if (raw > static_cast<unsigned long long>(std::numeric_limits<int>::max()))
        {
            error = std::string(key) + ": value out of range";
            return false;
        }
        out = static_cast<int>(raw);
        return true;
    }

    if (it->is_number_integer())
    {
        const long long raw = it->get<long long>();
        if (raw < std::numeric_limits<int>::min() ||
                raw > std::numeric_limits<int>::max())
        {
            error = std::string(key) + ": value out of range";
            return false;
        }
        out = static_cast<int>(raw);
        return true;
    }

    if (it->is_string())
    {
        const std::string text = trim(it->get<std::string>());
        if (text.empty())
            return true;

        char *end = nullptr;
        const long long value = std::strtoll(text.c_str(), &end, 10);
        if (end == nullptr || *end != '\0')
        {
            error = std::string(key) + ": not a number (\"" + text + "\")";
            return false;
        }
        if (value < std::numeric_limits<int>::min() ||
                value > std::numeric_limits<int>::max())
        {
            error = std::string(key) + ": value out of range";
            return false;
        }
        out = static_cast<int>(value);
        return true;
    }

    error = std::string(key) + ": expected an integer";
    return false;
}

/*
 *@brief 读取字节数字段(缺省 / 空串时保持 out 原值)
 */
bool read_size(const json &owner, const char *key, std::size_t &out, std::string &error)
{
    const auto it = owner.find(key);
    if (it == owner.end() || it->is_null())
        return true;

    unsigned long long value = 0;
    if (it->is_number_unsigned())
    {
        value = it->get<unsigned long long>();
    }
    else if (it->is_number_integer())
    {
        const long long raw = it->get<long long>();
        if (raw < 0)
        {
            error = std::string(key) + ": must not be negative";
            return false;
        }
        value = static_cast<unsigned long long>(raw);
    }
    else if (it->is_string())
    {
        const std::string text = trim(it->get<std::string>());
        if (text.empty())
            return true;

        if (text.front() == '-')
        {
            error = std::string(key) + ": must not be negative";
            return false;
        }

        errno = 0;
        char *end = nullptr;
        value = std::strtoull(text.c_str(), &end, 10);
        if (errno != 0 || end == nullptr || *end != '\0')
        {
            error = std::string(key) + ": not a number (\"" + text + "\")";
            return false;
        }
    }
    else
    {
        error = std::string(key) + ": expected a number";
        return false;
    }

    if (value > static_cast<unsigned long long>(std::numeric_limits<std::size_t>::max()))
    {
        error = std::string(key) + ": value out of range";
        return false;
    }
    out = static_cast<std::size_t>(value);
    return true;
}

/*
 *@brief 严格解析命令行里的字节数参数
 *@return false 表示不是合法的非负十进制整数(例如 "abc" / "12k" / "-1")
 *@note  旧实现用 std::atoll:非法文本会被当成 0,而 0 在本程序里的含义是
 *       "不限制" —— 一个手误(或攻击者控制的环境变量/脚本参数)就能悄悄
 *       关掉内存上限。这里改成严格校验,非法就直接报错退出。
 */
bool parse_size_arg(const char *text, std::size_t &out)
{
    if (text == nullptr || *text == '\0')
        return false;

    const std::string value = trim(text);
    if (value.empty() || value.front() == '-')
        return false;

    errno = 0;
    char *end = nullptr;
    const unsigned long long parsed = std::strtoull(value.c_str(), &end, 10);
    if (errno != 0 || end == nullptr || *end != '\0')
        return false;
    if (parsed > static_cast<unsigned long long>(std::numeric_limits<std::size_t>::max()))
        return false;

    out = static_cast<std::size_t>(parsed);
    return true;
}

/* ==================== 路由键解析 ==================== */

/*
 *@brief 把 "域名/路径" 形式的键拆成域名与路径
 *       "/路径"     -> 只有路径(默认域名表,对任意 Host 生效)
 *       "域名/路径" -> 前半段域名,后半段路径
 *       "域名"      -> 整串是域名,路径为 "/"
 *@note  路径结尾写 "*" 或 "**" 时按前缀处理:先把结尾的星号去掉,
 *       再按"/"结尾判定是否走 Distributor 的前缀匹配
 */
bool split_route_key(const std::string &key, std::string &host, std::string &path,
                     std::string &error)
{
    const std::string text = trim(key);
    if (text.empty())
    {
        error = "route key is empty";
        return false;
    }

    host.clear();
    if (text.front() != '/')
    {
        const std::size_t slash = text.find('/');
        if (slash == std::string::npos)
        {
            host = text;
            path = "/";
        }
        else
        {
            host = trim(text.substr(0, slash));
            path = text.substr(slash);
        }

        if (host.empty())
        {
            error = "route host is empty";
            return false;
        }
    }
    else
    {
        path = text;
    }

    // 前缀匹配由 Distributor 的 "/xxx/" 语义完成,这里把结尾通配符去掉
    while (path.size() > 1 && path.back() == '*')
        path.pop_back();
    if (path.empty())
        path = "/";
    if (path.front() != '/')
        path.insert(path.begin(), '/');
    return true;
}

/*
 *@brief 路由的可读文本(日志 / 控制台输出用)
 */
std::string route_label(const Route_config &route)
{
    return (route.host.empty() ? std::string("(default)") : route.host) + route.path;
}

/* ==================== 配置文件解析 ==================== */

/*
 *@brief 解析一个"脚本 + 文件 / SQL 权限"对象
 *       字段为 js_path / js_read_rule / js_write_rule / js_sql_read_rule /
 *       js_sql_write_rule / js_full_access
 *@note  路由处理器(http / websocket)与 base_msg 里的安全检测 / 全局数据脚本
 *       共用这套字段,权限配置方式与 roter 完全一致;
 *       字段缺省表示该类型不处理 / 不给该方向的权限,不算错误
 */
bool parse_script_object(const json &item, Script_config &out, std::string &error)
{
    std::string js_path;
    std::string read_rule;
    std::string write_rule;
    std::string sql_read_rule;
    std::string sql_write_rule;
    bool full_access = false;
    if (!read_text(item, "js_path", js_path, error) ||
            !read_text(item, "js_read_rule", read_rule, error) ||
            !read_text(item, "js_write_rule", write_rule, error) ||
            !read_text(item, "js_sql_read_rule", sql_read_rule, error) ||
            !read_text(item, "js_sql_write_rule", sql_write_rule, error) ||
            !read_bool(item, "js_full_access", full_access, error))
    {
        return false;
    }

    out.js_path = js_path;
    out.read_dirs = split_dirs(read_rule);
    out.write_dirs = split_dirs(write_rule);
    out.sql_read_dbs = split_dirs(sql_read_rule);
    out.sql_write_dbs = split_dirs(sql_write_rule);
    out.full_access = full_access;
    return true;
}

/*
 *@brief 解析一个处理器对象(含 js_path / js_read_rule / js_write_rule /
 *       js_sql_read_rule / js_sql_write_rule / js_full_access)
 *@note  字段缺省表示该类型不处理,不算错误
 */
bool parse_handler(const json &owner, const char *key, Script_config &out, std::string &error)
{
    const auto it = owner.find(key);
    if (it == owner.end() || it->is_null())
        return true;

    if (!it->is_object())
    {
        error = std::string(key) + ": expected an object";
        return false;
    }

    if (!parse_script_object(*it, out, error))
    {
        error = std::string(key) + "." + error;
        return false;
    }
    return true;
}

/*
 *@brief 解析 base_msg 里的脚本入口(js_security_script / js_global_script)
 *
 *@note  兼容两种写法:
 *         1) 字符串:只给脚本路径,权限取 legacy_full_access 指定的旧默认值;
 *         2) 对象  :字段与 roter 处理器完全一致,可以按 js_read_rule /
 *            js_write_rule / js_sql_read_rule / js_sql_write_rule /
 *            js_full_access 单独授予文件与 SQLite 权限(缺省 = 默认拒绝)。
 *       对象写法下 js_path 留空表示不启用该脚本。
 */
bool parse_script_entry(const json &owner, const char *key, Script_config &out,
                        bool legacy_full_access, std::string &error)
{
    const auto it = owner.find(key);
    if (it == owner.end() || it->is_null())
        return true;

    if (it->is_string())
    {
        out.js_path = trim(it->get<std::string>());
        out.full_access = legacy_full_access && !out.js_path.empty();
        return true;
    }

    if (!it->is_object())
    {
        error = std::string(key) +
                ": expected a string (script path) or an object (roter-style rules)";
        return false;
    }
    return parse_script_object(*it, out, error);
}

/*
 *@brief 解析 "roter" 数组:每项形如 { "域名/路径": { "http": {...}, "websocket": {...} } }
 *@note  一个对象里可以写多条路由。路由匹配只看"域名 + 路径 + 请求类型",
 *       与声明顺序无关(nlohmann::json 的对象键按字典序遍历)。
 *       同一路径、同一类型重复配置时最后一次生效,启动日志会告警;
 *       没配任何脚本的路由会被忽略(该路径继续走 undefine_roter / 404)
 */
bool parse_routes(const json &root, const char *key, std::vector<Route_config> &out,
                  std::string &error)
{
    const auto it = root.find(key);
    if (it == root.end() || it->is_null())
        return true;

    if (!it->is_array())
    {
        error = std::string(key) + ": expected an array";
        return false;
    }

    for (std::size_t i = 0; i < it->size(); ++i)
    {
        const json &item = (*it)[i];
        const std::string where = std::string(key) + "[" + std::to_string(i) + "]";
        if (!item.is_object())
        {
            error = where + ": expected an object";
            return false;
        }
        if (item.empty())
        {
            error = where + ": route object is empty";
            return false;
        }

        for (auto route_it = item.begin(); route_it != item.end(); ++route_it)
        {
            Route_config route;
            std::string key_error;
            if (!split_route_key(route_it.key(), route.host, route.path, key_error))
            {
                error = where + "." + route_it.key() + ": " + key_error;
                return false;
            }

            if (!parse_handler(route_it.value(), "http", route.http, error) ||
                    !parse_handler(route_it.value(), "websocket", route.websocket, error))
            {
                error = where + "." + route_it.key() + ": " + error;
                return false;
            }

            if (!route.enabled())
            {
                Log::warning("Hhttp: route " + route_label(route) + " has no js_path, ignored");
                continue;
            }
            out.push_back(std::move(route));
        }
    }
    return true;
}

/*
 *@brief 解析 "undefine_roter"(未匹配到路径时使用的处理器)
 */
bool parse_fallback(const json &root, const char *key, Route_config &out, std::string &error)
{
    const auto it = root.find(key);
    if (it == root.end() || it->is_null())
        return true;

    if (!it->is_object())
    {
        error = std::string(key) + ": expected an object";
        return false;
    }

    out.host.clear();
    out.path = "/";
    if (!parse_handler(*it, "http", out.http, error) ||
            !parse_handler(*it, "websocket", out.websocket, error))
    {
        error = std::string(key) + "." + error;
        return false;
    }
    return true;
}

/*
 *@brief 读取并解析整个配置文件
 *@param path   配置文件路径
 *@param config 输出
 *@param error  失败原因
 */
bool load_config(const std::string &path, App_config &config, std::string &error)
{
    std::ifstream in(std::filesystem::u8path(path), std::ios::binary);
    if (!in.is_open())
    {
        error = "cannot open config file: " + path;
        return false;
    }

    std::ostringstream buffer;
    buffer << in.rdbuf();
    const std::string text = buffer.str();
    if (trim(text).empty())
    {
        error = "config file is empty: " + path;
        return false;
    }

    json root;
    try
    {
        root = json::parse(text);
    }
    catch (const std::exception &e)
    {
        error = std::string("invalid JSON: ") + e.what();
        return false;
    }

    if (!root.is_object())
    {
        error = "config root must be an object";
        return false;
    }

    config.source_path = path;
    {
        std::error_code ec;
        const std::filesystem::path absolute =
            std::filesystem::absolute(std::filesystem::u8path(path), ec);
        config.source_dir = ec ? std::filesystem::u8path(path).parent_path().u8string()
                            : absolute.parent_path().u8string();
    }

    /* ---- base_msg:监听端口与证书 ---- */
    const auto base = root.find("base_msg");
    if (base != root.end() && !base->is_null())
    {
        if (!base->is_object())
        {
            error = "base_msg: expected an object";
            return false;
        }

        if (!read_int(*base, "HTTP_port", config.http_port, error) ||
                !read_int(*base, "HTTPS_port", config.https_port, error))
        {
            error = "base_msg." + error;
            return false;
        }

        std::string value;
        if (!read_text(*base, "pfx_path", value, error))
        {
            error = "base_msg." + error;
            return false;
        }
        config.pfx_path = value;

        if (!read_text(*base, "pfx_password", value, error))
        {
            error = "base_msg." + error;
            return false;
        }
        config.pfx_password = value;

        // 可选:PEM 证书链 + 私钥(与 pfx_path 二选一)
        if (!read_text(*base, "cert_file", value, error))
        {
            error = "base_msg." + error;
            return false;
        }
        config.cert_file = value;

        if (!read_text(*base, "key_file", value, error))
        {
            error = "base_msg." + error;
            return false;
        }
        config.key_file = value;

        /*
         * 可选:多证书(一个 HTTPS 端口可挂多张证书,按客户端 ClientHello 里的
         * SNI 域名自动选择;写在这里时 pfx_path / pfx_password 被忽略)
         *   "certificates": [
         *     { "pfx_path": "a.example.com.pfx", "pfx_password": "..." },
         *     { "pfx_path": "b.example.com.pfx", "pfx_password": "..." }
         *   ]
         */
        const auto certs_it = base->find("certificates");
        if (certs_it != base->end() && !certs_it->is_null())
        {
            if (!certs_it->is_array())
            {
                error = "base_msg.certificates: expected an array";
                return false;
            }
            for (std::size_t i = 0; i < certs_it->size(); ++i)
            {
                const json &item = (*certs_it)[i];
                const std::string where =
                    "base_msg.certificates[" + std::to_string(i) + "]";
                if (!item.is_object())
                {
                    error = where + ": expected an object";
                    return false;
                }

                Certificate_config cert;
                if (!read_text(item, "pfx_path", cert.pfx_path, error) ||
                        !read_text(item, "pfx_password", cert.pfx_password, error) ||
                        !read_text(item, "cert_file", cert.cert_file, error) ||
                        !read_text(item, "key_file", cert.key_file, error))
                {
                    error = where + "." + error;
                    return false;
                }
                // 一张证书要么给 PFX,要么给 PEM 证书 + 私钥
                const bool from_pfx = !cert.pfx_path.empty();
                const bool from_pem = !cert.cert_file.empty() && !cert.key_file.empty();
                if (!from_pfx && !from_pem)
                {
                    error = where + ": needs pfx_path, or cert_file + key_file";
                    return false;
                }
                config.certificates.push_back(std::move(cert));
            }
        }

        // 没写 certificates 时,把单证书写法归一成一张证书
        if (config.certificates.empty() &&
                (!config.pfx_path.empty() ||
                 (!config.cert_file.empty() && !config.key_file.empty())))
        {
            Certificate_config cert;
            cert.pfx_path = config.pfx_path;
            cert.pfx_password = config.pfx_password;
            cert.cert_file = config.cert_file;
            cert.key_file = config.key_file;
            config.certificates.push_back(std::move(cert));
        }

        // 可选:脚本目录(命令行 --dir 优先)
        if (!read_text(*base, "script_dir", value, error))
        {
            error = "base_msg." + error;
            return false;
        }
        if (!value.empty())
            config.script_dir = value;

        // 可选:脚本单次读取上限
        if (!read_size(*base, "file_max_size", config.file_max_size, error))
        {
            error = "base_msg." + error;
            return false;
        }

        // 可选:脚本执行超时(毫秒,0 表示不限制)
        if (!read_int(*base, "js_exec_timeout_ms", config.js_exec_timeout_ms, error) ||
                !read_int(*base, "websocket_recv_timeout_ms",
                          config.websocket_recv_timeout_ms, error))
        {
            error = "base_msg." + error;
            return false;
        }

        // 可选:脚本内存上限(字节,0 表示不限制)
        if (!read_size(*base, "js_memory_limit", config.js_memory_limit, error) ||
                !read_size(*base, "js_security_memory_limit",
                           config.js_security_memory_limit, error) ||
                !read_size(*base, "js_global_memory_limit",
                           config.js_global_memory_limit, error))
        {
            error = "base_msg." + error;
            return false;
        }


        // 可选:安全检测脚本
        //   字符串 = 只有脚本路径(默认没有任何文件 / SQL 权限);
        //   对象   = 与 roter 处理器一致的字段,可授予文件 / SQLite 权限
        if (!parse_script_entry(*base, "js_security_script", config.security_script,
                                false, error))
        {
            error = "base_msg." + error;
            return false;
        }

        // 可选:全局数据脚本
        //   字符串 = 只有脚本路径(沿用旧版本的完全文件 / SQL 权限);
        //   对象   = 与 roter 处理器一致的字段,可精确配置权限
        if (!parse_script_entry(*base, "js_global_script", config.global_script,
                                true, error))
        {
            error = "base_msg." + error;
            return false;
        }

        // 可选:彩色日志输出(缺省保持开启;不支持 ANSI 转义序列的终端可设为 false)
        if (!read_bool_keep(*base, "colorful_log", config.colorful_log, error))
        {
            error = "base_msg." + error;
            return false;
        }
    }

    // 证书相对路径以配置文件所在目录为基准(那里找不到时退回按当前工作目录解释)
    auto resolve_cert_path = [&config](std::string &path)
    {
        if (path.empty())
            return;
        const std::filesystem::path given = std::filesystem::u8path(path);
        if (!given.is_relative() || config.source_dir.empty())
            return;

        std::error_code ec;
        const std::filesystem::path candidate =
            (std::filesystem::u8path(config.source_dir) / given).lexically_normal();
        if (std::filesystem::is_regular_file(candidate, ec))
            path = candidate.u8string();
    };

    resolve_cert_path(config.pfx_path);
    resolve_cert_path(config.cert_file);
    resolve_cert_path(config.key_file);
    for (Certificate_config &cert : config.certificates)
    {
        resolve_cert_path(cert.pfx_path);
        resolve_cert_path(cert.cert_file);
        resolve_cert_path(cert.key_file);
    }

    /* ---- roter:路由表 ---- */
    const char *route_key = root.contains("roter")
                            ? "roter" : (root.contains("router") ? "router" : "roter");
    if (!parse_routes(root, route_key, config.routes, error))
        return false;

    /* ---- undefine_roter:兜底处理器 ---- */
    const char *fallback_key = root.contains("undefine_roter")
                               ? "undefine_roter"
                               : (root.contains("undefined_router") ? "undefined_router"
                                  : "undefine_roter");
    if (!parse_fallback(root, fallback_key, config.fallback, error))
        return false;

    return true;
}

/* ==================== 脚本路径与文件访问规则 ==================== */

/*
 *@brief 把配置里的 js_path 解析成绝对路径
 *       相对路径以脚本目录(--dir / base_msg.script_dir)为基准
 */
std::string resolve_script_path(const std::string &script_dir, const std::string &js_path)
{
    const std::filesystem::path given = std::filesystem::u8path(js_path);
    const std::filesystem::path full = given.is_absolute()
                                       ? given
                                       : (std::filesystem::u8path(script_dir) / given);

    std::error_code ec;
    const std::filesystem::path fixed = std::filesystem::weakly_canonical(full, ec);
    if (ec || fixed.empty())
        return full.lexically_normal().u8string();
    return fixed.u8string();
}

/*
 *@brief 解析所有配置里的脚本路径,并给出"脚本不存在"的告警
 */
void resolve_scripts(App_config &config)
{
    auto resolve = [&config](Script_config &script, const std::string &label)
    {
        if (!script.enabled())
            return;

        script.js_path = resolve_script_path(config.script_dir, script.js_path);

        std::error_code ec;
        if (!std::filesystem::is_regular_file(std::filesystem::u8path(script.js_path), ec))
        {
            Log::warning("Hhttp: script not found: " + script.js_path +
                         " (" + label + ")");
        }
    };

    for (Route_config &route : config.routes)
    {
        const std::string label = route_label(route);
        resolve(route.http, label);
        resolve(route.websocket, label);
    }
    resolve(config.fallback.http, "undefine_roter");
    resolve(config.fallback.websocket, "undefine_roter");
    resolve(config.security_script, "js_security_script");
    resolve(config.global_script, "js_global_script");
}

/*
 *@brief 计算脚本相对脚本目录的键(JS 侧规则匹配用):统一 '/',转小写
 *@return 空串表示脚本不在脚本目录内(此时该脚本的文件访问一律被拒绝)
 */
std::string script_key(const std::string &script_path, const std::string &script_dir)
{
    if (script_path.empty() || script_dir.empty())
        return std::string();

    std::error_code ec;
    const std::filesystem::path script =
        std::filesystem::weakly_canonical(std::filesystem::u8path(script_path), ec);
    if (ec || script.empty())
        return std::string();

    const std::filesystem::path root =
        std::filesystem::weakly_canonical(std::filesystem::u8path(script_dir), ec);
    if (ec || root.empty())
        return std::string();

    const std::filesystem::path rel = script.lexically_relative(root);
    if (rel.empty())
        return std::string();

    std::string text = rel.generic_u8string();
    if (text == ".." || text.rfind("../", 0) == 0)
        return std::string();

    while (!text.empty() && text.front() == '/')
        text.erase(0, 1);
    while (text.size() >= 2 && text[0] == '.' && text[1] == '/')
        text.erase(0, 2);
    return to_lower_copy(text);
}

/*
 *@brief 新增一条脚本规则;同一脚本被多条路由引用时目录取并集
 *@note  JS 的文件策略是进程级、按"脚本相对路径"匹配的,同一脚本只能有一条规则
 */
void add_policy_rule(std::vector<JS::File_rule> &rules, const std::string &key,
                     const std::vector<std::string> &read_dirs,
                     const std::vector<std::string> &write_dirs)
{
    if (key.empty())
        return;

    for (JS::File_rule &rule : rules)
    {
        if (rule.script != key)
            continue;

        for (const std::string &dir : read_dirs)
        {
            if (std::find(rule.read_dirs.begin(), rule.read_dirs.end(), dir) ==
                    rule.read_dirs.end())
            {
                rule.read_dirs.push_back(dir);
            }
        }
        for (const std::string &dir : write_dirs)
        {
            if (std::find(rule.write_dirs.begin(), rule.write_dirs.end(), dir) ==
                    rule.write_dirs.end())
            {
                rule.write_dirs.push_back(dir);
            }
        }
        return;
    }

    JS::File_rule rule;
    rule.script = key;
    rule.read_dirs = read_dirs;
    rule.write_dirs = write_dirs;
    rules.push_back(std::move(rule));
}

/*
 *@brief 由配置生成 JS 文件访问规则:每个脚本一条,权限来自 js_read_rule / js_write_rule
 */
std::vector<JS::File_rule> build_file_rules(const App_config &config)
{
    std::vector<JS::File_rule> rules;

    auto add_script = [&config, &rules](const Script_config &script)
    {
        if (!script.enabled())
            return;

        const std::string key = script_key(script.js_path, config.script_dir);
        if (key.empty())
        {
            // 脚本不在 --dir 内:只有 js_full_access 才能绕过这个限制
            if (!script.full_access)
                Log::warning("Hhttp: script " + script.js_path +
                             " is outside the script directory, file access denied");
            return;
        }
        add_policy_rule(rules, key, script.read_dirs, script.write_dirs);
    };

    for (const Route_config &route : config.routes)
    {
        add_script(route.http);
        add_script(route.websocket);
    }
    add_script(config.fallback.http);
    add_script(config.fallback.websocket);
    add_script(config.security_script);
    add_script(config.global_script);
    return rules;
}

/*
 *@brief 由配置生成 JS SQL 访问规则:每个脚本一条,权限来自 js_sql_read_rule /
 *       js_sql_write_rule(数据库路径模式,相对路径以 --dir 为基准,也可写绝对路径)
 */
std::vector<JS::Sql_rule> build_sql_rules(const App_config &config)
{
    std::vector<JS::Sql_rule> rules;

    auto add_script = [&config, &rules](const Script_config &script)
    {
        if (!script.enabled())
            return;
        if (script.sql_read_dbs.empty() && script.sql_write_dbs.empty())
            return;

        const std::string key = script_key(script.js_path, config.script_dir);
        if (key.empty())
        {
            // 脚本不在 --dir 内:只有 js_full_access 才能绕过这个限制
            if (!script.full_access)
                Log::warning("Hhttp: script " + script.js_path +
                             " is outside the script directory, sql access denied");
            return;
        }

        for (JS::Sql_rule &rule : rules)
        {
            if (rule.script != key)
                continue;
            for (const std::string &db : script.sql_read_dbs)
            {
                if (std::find(rule.read_dbs.begin(), rule.read_dbs.end(), db) ==
                        rule.read_dbs.end())
                {
                    rule.read_dbs.push_back(db);
                }
            }
            for (const std::string &db : script.sql_write_dbs)
            {
                if (std::find(rule.write_dbs.begin(), rule.write_dbs.end(), db) ==
                        rule.write_dbs.end())
                {
                    rule.write_dbs.push_back(db);
                }
            }
            return;
        }

        JS::Sql_rule rule;
        rule.script = key;
        rule.read_dbs = script.sql_read_dbs;
        rule.write_dbs = script.sql_write_dbs;
        rules.push_back(std::move(rule));
    };

    for (const Route_config &route : config.routes)
    {
        add_script(route.http);
        add_script(route.websocket);
    }
    add_script(config.fallback.http);
    add_script(config.fallback.websocket);
    add_script(config.security_script);
    add_script(config.global_script);
    return rules;
}

/*
 *@brief 收集被授予"完全访问"的脚本:js_full_access = true 的脚本
 *@note  路径规范化为绝对路径、统一 '/'、转小写,与 JS 侧的判定方式一致
 */
std::vector<std::string> build_full_access_scripts(const App_config &config)
{
    std::vector<std::string> scripts;

    auto add_script = [&scripts](const Script_config &script)
    {
        if (!script.enabled() || !script.full_access)
            return;

        std::error_code ec;
        const std::filesystem::path path =
            std::filesystem::weakly_canonical(std::filesystem::u8path(script.js_path), ec);
        if (ec || path.empty())
        {
            Log::warning("Hhttp: full access script has an invalid path: " + script.js_path);
            return;
        }

        // 注意:不能去掉开头的 '/':POSIX 下那会让绝对路径变成相对路径,
        // 与 JS 侧 current_script_abs() 的规范化结果对不上
        const std::string text = to_lower_copy(path.generic_u8string());

        if (std::find(scripts.begin(), scripts.end(), text) == scripts.end())
            scripts.push_back(std::move(text));
    };

    for (const Route_config &route : config.routes)
    {
        add_script(route.http);
        add_script(route.websocket);
    }
    add_script(config.fallback.http);
    add_script(config.fallback.websocket);
    add_script(config.security_script);
    add_script(config.global_script);
    return scripts;
}

/* ==================== 监听服务 ==================== */

/*
 *@brief 为一个路由生成 ScriptRouter
 */
std::shared_ptr<ScriptRouter> make_router(const Route_config &route)
{
    return std::make_shared<ScriptRouter>(route.http.js_path, route.websocket.js_path);
}

/*
 *@brief 把配置文件里的一条路由注册到 Distributor
 *@note  HTTP 与 WebSocket 写入各自的槽位:同一路径即使在配置里拆成两条
 *       (一条只写 http、一条只写 websocket)也能同时生效。
 *       若两种脚本写在同一个对象里,则用一个 ScriptRouter 同时处理两种类型
 */
void register_one_route(HTTP::Distributor &distributor, const Route_config &route)
{
    const bool has_http = route.http.enabled();
    const bool has_ws = route.websocket.enabled();

    if (has_http)
    {
        // 两种都配时由 ScriptRouter 内部按类型分派到 JS_HTTP / JS_WS
        std::shared_ptr<ScriptRouter> router =
            std::make_shared<ScriptRouter>(route.http.js_path,
                                           has_ws ? route.websocket.js_path : std::string());
        if (route.host.empty())
            distributor.add_router(route.path, router);
        else
            distributor.add_router(route.host, route.path, router);
        return;
    }

    // 只有 WebSocket 脚本:注册到 WebSocket 专用槽位,不覆盖同路径的 HTTP 处理器
    std::shared_ptr<ScriptRouter> router =
        std::make_shared<ScriptRouter>(std::string(), route.websocket.js_path);
    HTTP::Distributor::WsHandler handler =
        [router](HTTP::WebSocket &ws, const HTTP::Header_get &header)
    {
        router->handle_websocket(ws, header);
    };
    if (route.host.empty())
        distributor.add_websocket_router(route.path, handler);
    else
        distributor.add_websocket_router(route.host, route.path, handler);
}

/*
 *@brief 把配置文件里的路由表注册到 Distributor
 *@note  undefine_roter 同时挂到"默认域名表"和每个已注册域名上:框架的语义是
 *       域名专属表命中后不再回退默认表,所以必须逐个域名安装
 */
void register_routes(HTTP::Distributor &distributor, const App_config &config)
{
    std::set<std::string> hosts;

    for (const Route_config &route : config.routes)
    {
        register_one_route(distributor, route);
        if (!route.host.empty())
            hosts.insert(route.host);
    }

    if (!config.fallback.enabled())
        return; // 未配置 undefine_roter:保持框架默认的 404

    std::shared_ptr<ScriptRouter> fallback = make_router(config.fallback);
    distributor.set_not_found_router(fallback);
    for (const std::string &host : hosts)
        distributor.set_not_found_router(host, fallback);
}

/*
 *@struct Listener
 *@brief 一个监听端口及其分发器
 */
struct Listener
{
    std::unique_ptr<TCP::Server> server;            ///< TCP 监听
    std::unique_ptr<HTTP::Distributor> distributor; ///< HTTP/WebSocket 分发器
    int port = 0;                                   ///< 监听端口
    bool tls = false;                               ///< 是否 HTTPS/WSS
};

/*
 *@brief 创建并启动一个监听端口
 *@param listeners 监听列表(成功后追加)
 *@param port      端口
 *@param tls       是否启用 TLS
 *@param tls_ctx   TLS 上下文(tls 为 true 时必需)
 *@param config    配置
 *@return 成功返回 true
 */
bool start_listener(std::vector<Listener> &listeners, int port, bool tls,
                    const std::shared_ptr<TLS::Context> &tls_ctx, const App_config &config)
{
    Listener listener;
    listener.port = port;
    listener.tls = tls;
    // TCP::Server 负责 socket 创建、绑定与监听(底层是 Boost.Asio)
    listener.server = std::make_unique<TCP::Server>(
                          static_cast<unsigned short>(port));
    if (!listener.server->valid())
    {
        Log::error("Hhttp: failed to listen on port " + std::to_string(port));
        return false;
    }

    listener.distributor = std::make_unique<HTTP::Distributor>(*listener.server);
    HTTP::Distributor &distributor = *listener.distributor;
    distributor.set_keep_alive(true);
    distributor.set_read_timeout_ms(30000);
    if (tls)
        distributor.set_tls(tls_ctx);

    register_routes(distributor, config);

    // 安全检测过滤器:配置了 base_msg.js_security_script 时,每个监听端口挂一份
    if (config.security_script.enabled())
    {
        std::string filter_error;
        std::shared_ptr<HTTP::RequestFilter> filter =
            JS::make_security_filter(config.security_script.js_path, filter_error);
        if (!filter)
        {
            Log::error("Hhttp: invalid security script: " + filter_error);
            return false;
        }
        distributor.add_filter(std::move(filter));
    }

    distributor.start();

    listeners.push_back(std::move(listener));
    return true;
}

/*
 *@brief 校验端口是否可用
 */
bool valid_port(int port)
{
    return port > 0 && port <= 65535;
}

void print_usage(const char *prog)
{
    // 统一走 LOG 库输出:与控制台其余信息同格式,并同时落盘 LOG/<日期>.txt
    // 控制台输出统一用 ASCII(Windows 控制台默认 cp936,中文会乱码)
    const std::string usage =
        std::string("usage: ") + prog +
        " [--config CONFIG_JSON] [--dir SCRIPTS_DIR]\n"
        "         [--file-max-size BYTES]\n"
        "         [--js-memory-limit BYTES] [--js-security-memory-limit BYTES]\n"
        "         [--js-global-memory-limit BYTES]\n"
        "  defaults: --config config.json --dir scripts --file-max-size 8388608\n"
        "            --js-memory-limit 67108864 --js-security-memory-limit 67108864\n"
        "            --js-global-memory-limit 134217728\n"
        "  Ports, hosts, routes, scripts and per-script file/SQLite permissions come\n"
        "  from the JSON config file:\n"
        "    base_msg.HTTP_port / HTTPS_port / pfx_path / pfx_password\n"
        "      optional: certificates (multi-cert array selected by SNI; each item is\n"
        "                { \"pfx_path\": \"a.pfx\", \"pfx_password\": \"...\" } or\n"
        "                { \"cert_file\": \"a.crt\", \"key_file\": \"a.key\" } (PEM);\n"
        "                when present, the single-cert fields are ignored),\n"
        "                cert_file / key_file (single-cert PEM form),\n"
        "                script_dir (same as --dir), file_max_size (same as\n"
        "                --file-max-size),\n"
        "                js_memory_limit / js_security_memory_limit /\n"
        "                js_global_memory_limit (bytes, 0 = unlimited; same as the\n"
        "                three --js-*-memory-limit options),\n"
        "                js_exec_timeout_ms / websocket_recv_timeout_ms\n"
        "                (milliseconds, 0 = unlimited),\n"
        "                js_security_script (request check script),\n"
        "                js_global_script (global data script),\n"
        "                colorful_log (ANSI colors on the console, default true;\n"
        "                set false for terminals without ANSI support)\n"
        "    roter[]          : { \"host/path\": { \"http\": {...}, \"websocket\": {...} } }\n"
        "    undefine_roter   : handler used when no route matches\n"
        "  Handler fields (also accepted by js_security_script / js_global_script\n"
        "  when they are written as objects):\n"
        "    js_path          : script path (relative to --dir, or absolute; empty =\n"
        "                       this handler is disabled)\n"
        "    js_read_rule     : directories the script may read, separated by ',' or\n"
        "                       ';', relative to --dir; empty = reading denied\n"
        "    js_write_rule    : directories the script may write; same syntax and\n"
        "                       empty = writing denied\n"
        "    js_sql_read_rule : SQLite databases the script may open read-only;\n"
        "                       absolute paths and * / ** wildcards allowed\n"
        "    js_sql_write_rule: SQLite databases the script may open read-write;\n"
        "                       same syntax, empty = writing denied\n"
        "    js_full_access   : true = unrestricted file system and any SQLite\n"
        "                       database (high risk, default false; overrides the\n"
        "                       four rules above)\n"
        "  Request check script (base_msg.js_security_script):\n"
        "    must define check(req): true/undefined = allow | false = 403 | number =\n"
        "    use that status code | {allow,status,message,headers} = full control;\n"
        "    exceptions/timeouts are answered with 500. req also exposes HTTPS\n"
        "    helpers: isHttps(), scheme(), tlsProtocol().\n"
        "  Global data script (base_msg.js_global_script):\n"
        "    functions defined on globalThis are callable from web scripts with\n"
        "    Global.call(name, args). A plain string path keeps the legacy full\n"
        "    file/SQLite access; write it as an object to configure rules.\n"
        "  Route keys:\n"
        "    \"localhost/index\" -> this host only; \"*.abc.com/api/\" -> wildcard\n"
        "    subdomain + prefix match\n"
        "    \"/index\"            -> default host table, matches any Host header\n"
        "  A path ending with / (or with * / **) matches by prefix\n"
        "  HTTPS: enabled only when base_msg.HTTPS_port and a certificate (PFX or PEM\n"
        "         cert_file+key_file) are both given. One certificate usually covers one host;\n"
        "         with several route hosts use certificates so the server can pick\n"
        "         the right one by SNI. Relative pfx paths are resolved against the\n"
        "         config file directory.\n"
        "  JS can check whether the current connection is HTTPS:\n"
        "    HTTP.get.isHttps() / HTTP.get.scheme() / HTTP.get.tlsProtocol()\n"
        "  note:  relative --config / --dir paths are looked up in the current\n"
        "         directory first, then next to the executable and its parent\n";
    Log::log(usage);
}

/*
 *@brief 排空日志队列后再退出进程
 *@param code 进程退出码(原样返回)
 *@note  --help / 参数或配置错误等分支会在主线程立即 return;如果只依赖
 *       Log 内部的静态 stopper 在 CRT 退出阶段排空队列,日志线程可能在
 *       静态析构期间访问 C 运行库的锁而死锁(表现为进程卡住不退出)。
 *       在 return 之前显式停掉日志线程可以避开这个窗口;
 *       stop_output 重复调用无副作用,静态 stopper 随后会直接跳过。
 */
int exit_after_log_flush(int code)
{
    Log::stop_output();
    return code;
}

} // namespace

int main(int argc, char *argv[])
{
    // 先启动日志线程:--help / 参数错误等早退分支同样需要经 LOG 库输出
    // (退出前由 exit_after_log_flush 主动排空队列,避免静态析构阶段的死锁)
    Log::start_output();

    std::string config_path = "config.json";
    std::string dir;
    std::size_t file_max_size = 0;
    std::size_t js_memory_limit = 0;
    std::size_t js_security_memory_limit = 0;
    std::size_t js_global_memory_limit = 0;
    bool js_limit_given = false;
    bool js_security_limit_given = false;
    bool js_global_limit_given = false;
    bool dir_given = false;
    bool size_given = false;

    for (int i = 1; i < argc; ++i)
    {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h")
        {
            print_usage(argv[0]);
            return exit_after_log_flush(0);
        }
        if ((arg == "--config" || arg == "-c") && i + 1 < argc)
        {
            config_path = argv[++i];
        }
        else if (arg == "--dir" && i + 1 < argc)
        {
            dir = argv[++i];
            dir_given = true;
        }
        else if (arg == "--js-memory-limit" && i + 1 < argc)
        {
            if (!parse_size_arg(argv[++i], js_memory_limit))
            {
                Log::error(std::string("invalid --js-memory-limit: ") + argv[i]);
                return exit_after_log_flush(1);
            }
            js_limit_given = true;
        }
        else if (arg == "--js-security-memory-limit" && i + 1 < argc)
        {
            if (!parse_size_arg(argv[++i], js_security_memory_limit))
            {
                Log::error(std::string("invalid --js-security-memory-limit: ") + argv[i]);
                return exit_after_log_flush(1);
            }
            js_security_limit_given = true;
        }
        else if (arg == "--js-global-memory-limit" && i + 1 < argc)
        {
            if (!parse_size_arg(argv[++i], js_global_memory_limit))
            {
                Log::error(std::string("invalid --js-global-memory-limit: ") + argv[i]);
                return exit_after_log_flush(1);
            }
            js_global_limit_given = true;
        }

        else if (arg == "--file-max-size" && i + 1 < argc)
        {
            if (!parse_size_arg(argv[++i], file_max_size))
            {
                Log::error(std::string("invalid --file-max-size: ") + argv[i]);
                return exit_after_log_flush(1);
            }
            size_given = true;
        }
        else
        {
            Log::error(std::string("unknown argument: ") + arg);
            print_usage(argv[0]);
            return exit_after_log_flush(1);
        }
    }

    /* ---- 1. 读取配置文件 ---- */
    config_path = resolve_input_path(config_path, false);
    App_config config;
    std::string error;
    bool config_ok = false;
    try
    {
        config_ok = load_config(config_path, config, error);
    }
    catch (const std::exception &e)
    {
        // json 库在极端取值(超范围整数等)上可能抛异常:
        // 配置错误只应该让进程打印原因后退出,而不是 std::terminate
        error = std::string("cannot parse config: ") + e.what();
        config_ok = false;
    }
    if (!config_ok)
    {
        Log::error("Hhttp: " + error);
        Log::error("Hhttp: please copy the sample config and edit it, or use --config");
        return exit_after_log_flush(1);
    }

    /* ---- 1.5 彩色日志输出 ---- */
    // 配置读取生效前保持默认开启(仅影响控制台着色,不影响落盘日志)
    Log::set_colorful(config.colorful_log);

    /* ---- 2. 脚本目录 ---- */
    if (!dir_given)
        dir = config.script_dir; // 默认 "scripts",可被 base_msg.script_dir 覆盖

    dir = resolve_input_path(dir, true);
    {
        std::error_code ec;
        // 统一成绝对路径:JS 侧要靠它反推"脚本相对 --dir 的路径"来做规则匹配
        const std::filesystem::path absolute =
            std::filesystem::absolute(std::filesystem::u8path(dir), ec);
        if (!ec && !absolute.empty())
            dir = absolute.lexically_normal().u8string();
    }
    {
        std::error_code ec;
        if (!std::filesystem::is_directory(std::filesystem::u8path(dir), ec))
            Log::warning("Hhttp: script directory not found: " + dir);
    }
    config.script_dir = dir;

    if (size_given)
        config.file_max_size = file_max_size;

    if (js_limit_given)
        config.js_memory_limit = js_memory_limit;
    if (js_security_limit_given)
        config.js_security_memory_limit = js_security_memory_limit;
    if (js_global_limit_given)
        config.js_global_memory_limit = js_global_memory_limit;

    /* ---- 3. 脚本路径与文件访问策略 ---- */
    resolve_scripts(config);

    {
        JS::File_policy policy;
        policy.script_dir = config.script_dir;
        policy.max_read_size = config.file_max_size;
        policy.rules = build_file_rules(config);
        policy.sql_rules = build_sql_rules(config);
        policy.full_access_scripts = build_full_access_scripts(config);
        JS::set_file_rules(std::move(policy));
    }

    /* ---- 3.5 脚本超时 ---- */
    if (config.js_exec_timeout_ms < 0 || config.websocket_recv_timeout_ms < 0)
    {
        Log::error("Hhttp: js_exec_timeout_ms / websocket_recv_timeout_ms must be >= 0");
        return exit_after_log_flush(1);
    }
    {
        JS::Timeouts timeouts;
        timeouts.js_exec_ms = config.js_exec_timeout_ms;
        timeouts.websocket_recv_ms = config.websocket_recv_timeout_ms;
        JS::set_timeouts(timeouts);
    }


    /* ---- 3.6 脚本内存上限 ---- */
    {
        JS::Limits limits;
        limits.request_bytes = config.js_memory_limit;
        limits.security_bytes = config.js_security_memory_limit;
        limits.global_bytes = config.js_global_memory_limit;

        // 0 表示"不限制",与 JS::Limits 的约定一致,直接透传
        JS::set_limits(limits);

        // 让用户能从启动日志确认三个上限是否按预期生效(0 表示不限制)
        Log::log("Hhttp: script memory limits (bytes): request=" +
                 std::to_string(config.js_memory_limit) + ", security=" +
                 std::to_string(config.js_security_memory_limit) + ", global=" +
                 std::to_string(config.js_global_memory_limit) + " (0 = unlimited)");
    }


    /* ---- 4. 端口与证书校验 ---- */
    if (config.http_port == 0 && config.https_port == 0)
    {
        Log::error("Hhttp: no listen port configured "
                   "(base_msg.HTTP_port / base_msg.HTTPS_port are both empty)");
        return exit_after_log_flush(1);
    }
    if (config.http_port != 0 && !valid_port(config.http_port))
    {
        Log::error("Hhttp: invalid HTTP_port: " + std::to_string(config.http_port));
        return exit_after_log_flush(1);
    }
    if (config.https_port != 0 && !valid_port(config.https_port))
    {
        Log::error("Hhttp: invalid HTTPS_port: " + std::to_string(config.https_port));
        return exit_after_log_flush(1);
    }
    if (config.http_port != 0 && config.http_port == config.https_port)
    {
        Log::error("Hhttp: HTTP_port and HTTPS_port must be different");
        return exit_after_log_flush(1);
    }

    std::shared_ptr<TLS::Context> tls_ctx;
    if (!config.certificates.empty())
    {
        if (!TLS::available())
        {
            Log::warning("Hhttp: TLS is not available on this platform, HTTPS/WSS disabled");
            config.https_port = 0;
        }
        else
        {
            TLS::Server_config tls_config;
            for (const Certificate_config &cert : config.certificates)
            {
                TLS::Cert_source source;
                source.pfx_path = cert.pfx_path;
                source.pfx_password = cert.pfx_password;
                source.cert_file = cert.cert_file;
                source.key_file = cert.key_file;
                tls_config.certs.push_back(std::move(source));
            }

            std::string tls_error;
            tls_ctx = TLS::make_server_context(tls_config, tls_error);
            if (!tls_ctx)
            {
                Log::error("Hhttp: failed to create TLS context: " + tls_error);
                return exit_after_log_flush(1);
            }

            Log::log("Hhttp: TLS certificates loaded: " +
                     std::to_string(tls_ctx->certificate_count()) +
                     (config.certificates.size() > 1
                      ? " (selected by SNI, the first one is the default)" : ""));
            for (const Certificate_config &cert : config.certificates)
            {
                Log::log("  cert: " + (cert.pfx_path.empty()
                                       ? cert.cert_file + " + " + cert.key_file
                                       : cert.pfx_path));
            }

            /*
             * 一个 PFX 通常只对应一个域名。路由里出现多个域名、又没有为每个域名
             * 配证书时,握手仍然会成功,但拿到的是默认证书,浏览器会提示
             * "证书域名不符"。这里启动期就逐个检查并告警,便于提前发现。
             */
            std::set<std::string> checked_hosts;
            for (const Route_config &route : config.routes)
            {
                if (route.host.empty())
                    continue; // 默认域名表,任意 Host 都能匹配,无需检查
                if (!checked_hosts.insert(route.host).second)
                    continue;
                if (!tls_ctx->covers_host(route.host))
                {
                    Log::warning("Hhttp: route host \"" + route.host +
                                 "\" is not covered by any configured certificate; "
                                 "HTTPS clients will get a certificate error. "
                                 "Add a certificate for it in base_msg.certificates");
                }
            }
        }
    }
    else if (config.https_port != 0)
    {
        Log::warning("Hhttp: base_msg.HTTPS_port is set but no certificate is configured "
                     "(base_msg.pfx_path / base_msg.certificates), HTTPS/WSS disabled");
        config.https_port = 0;
    }

    /* ---- 4.5 装载全局数据脚本 ---- */
    if (config.global_script.enabled())
    {
        JS::Global_options global_options;
        global_options.script_path = config.global_script.js_path;

        std::string global_error;
        if (!JS::start_global(global_options, global_error))
        {
            Log::error("Hhttp: failed to start global script: " + global_error);
            return exit_after_log_flush(1);
        }
        Log::log("Hhttp: global script loaded: " + config.global_script.js_path);
    }

    /* ---- 5. 启动监听 ---- */
    std::vector<Listener> listeners;
    if (config.http_port != 0 &&
            !start_listener(listeners, config.http_port, false, nullptr, config))
    {
        return exit_after_log_flush(1);
    }
    if (config.https_port != 0 &&
            !start_listener(listeners, config.https_port, true, tls_ctx, config))
    {
        for (Listener &listener : listeners)
            listener.distributor->stop();
        return exit_after_log_flush(1);
    }

    /* ---- 6. 启动信息 ---- */
    Log::log("Hhttp: config file: " + config.source_path);
    Log::log("Hhttp: script directory: " + config.script_dir);
    Log::log("Hhttp: routes: " + std::to_string(config.routes.size()) +
             (config.fallback.enabled() ? ", undefine_roter: enabled"
              : ", undefine_roter: 404"));
    for (const Route_config &route : config.routes)
    {
        Log::log("Hhttp: route " + route_label(route) +
                 ", http: " + (route.http.enabled() ? route.http.js_path
                               : std::string("(none)")) +
                 ", websocket: " + (route.websocket.enabled() ? route.websocket.js_path
                                    : std::string("(none)")));
    }
    if (config.security_script.enabled())
        Log::log("Hhttp: security script: " + config.security_script.js_path);
    if (config.global_script.enabled())
        Log::log("Hhttp: global script: " + config.global_script.js_path);

    Log::log(std::string("Hhttp is running\n") +
             "  config:      " + config.source_path + "\n" +
             "  script dir:  " + config.script_dir + "\n" +
             "  security:    " +
             (config.security_script.enabled() ? config.security_script.js_path
              : std::string("(none)")) + "\n" +
             "  global:      " +
             (config.global_script.enabled() ? config.global_script.js_path
              : std::string("(none)")) + "\n" +
             "  file rules:  " + std::to_string(JS::get_file_policy().rules.size()) + "\n" +
             "  max read:    " + std::to_string(config.file_max_size) + " bytes\n" +
             "  js memory:   " + std::to_string(JS::get_limits().request_bytes) + " / " +
             std::to_string(JS::get_limits().security_bytes) + " / " +
             std::to_string(JS::get_limits().global_bytes) + " bytes");
    for (const Listener &listener : listeners)
    {
        Log::log(std::string("  ") +
                 (listener.tls ? "https port: " : "http port:  ") +
                 std::to_string(listener.port));
    }
    for (const Route_config &route : config.routes)
    {
        Log::log(std::string("  route:       ") + route_label(route) +
                 "  http=" + (route.http.enabled() ? route.http.js_path : std::string("-")) +
                 "  ws=" + (route.websocket.enabled() ? route.websocket.js_path
                            : std::string("-")));
    }
    Log::log("press Enter to stop...");

    // 前台运行时按回车退出;stdin 已关闭(后台/重定向)时退化为常驻运行
    std::string line;
    if (std::getline(std::cin, line))
    {
        for (Listener &listener : listeners)
            listener.distributor->stop();
    }
    else
    {
        for (;;)
        {
            std::this_thread::sleep_for(std::chrono::hours(1));
        }
    }
    return exit_after_log_flush(0);
}
