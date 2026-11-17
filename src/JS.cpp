#include "JS.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <sqlite3.h>

#include "Log.h"
#include "WebSocket.h"

/*
 * ============================================================================
 * 脚本执行环境概览
 *
 *   HTTP.get   —— 只读的请求信息(绑定到当前 JS_HTTP::Header / Link)
 *   HTTP.send  —— 响应对象(绑定到当前 JS_HTTP::Send,并持有"是否已发送"标志)
 *   Cookie     —— new Cookie(name, value),可直接传给 HTTP.send.cookie(...)
 *   ws         —— WebSocket 连接对象(仅 JS_WS 环境)
 *   console.*  —— log / debug / warn / error / access,转发到框架 Log::*
 *
 * 生命周期约定:
 *   - JS_HTTP / JS_WS 每次执行都会新建 JSRuntime + JSContext,执行完立即释放;
 *   - 桥接对象里保存的只有 C++ 侧的指针/引用,它们都指向构造桥接对象之前就已存在、
 *     且直到脚本执行结束都不会失效的成员(Header / Link / Send / Ws);
 *   - 自定义类(Cookie / HTTPGet / HTTPSend)都是"非持有型"的:
 *     finalizer 只把对象指针从 JS 值上摘除,不 delete 它们;
 *     因此不能在脚本里长期保存这些对象(运行时随脚本一起销毁,无意义)。
 *
 * 并发约定(File.* 的线程安全):
 *   - 每个请求 / 连接一个线程,各自新建 JSRuntime + JSContext,互不共享;
 *   - 进程级共享的只有两样东西,都由锁保护:
 *       * 文件访问策略:shared_ptr<const File_policy> + shared_mutex,
 *         set_file_rules 整体替换一个新对象,读侧只拷一个指针;
 *       * 文件读写锁表:按路径分片的 std::shared_mutex;
 *   - File.* 在同一路径上可以多线程并行读,写则独占:
 *       同一路径的 read / readText / exists / size / list / send.file 互不阻塞;
 *       同一路径的 write / append / remove / mkdir 之间以及和读之间互斥,
 *       因此不会出现 "两个线程同时 truncate + 写导致内容交错",
 *       也不会读到写了一半的文件。
 * ============================================================================
 */

namespace
{

// ==================== 文件访问策略 ====================

/*
 *@brief 当前策略
 *
 *@note  用 shared_ptr<const T> 持有:set_file_rules 时整体替换成一个新对象,
 *       读侧只拷一个指针(不复制整张规则表),而且正在执行的脚本会一直用
 *       它拿到的那个版本,不会读到 "改了一半" 的策略。
 */
std::shared_ptr<const JS::File_policy> g_file_policy =
    std::make_shared<const JS::File_policy>();
std::shared_mutex g_file_policy_mutex; ///< 保护 g_file_policy 的替换 / 读取

// 当前正在执行的脚本(每个线程同一时刻只跑一个脚本,thread_local 足够用),
// File.* 靠它找出对应的规则
thread_local std::string t_current_script;

/*
 *@brief 策略快照(线程安全,返回值永远非空)
 *@note  快照是 shared_ptr,在整个操作期间都有效,规则表不会被提前回收
 */
std::shared_ptr<const JS::File_policy> file_policy_snapshot()
{
    std::shared_lock<std::shared_mutex> lock(g_file_policy_mutex);
    return g_file_policy;
}

/*
 *@brief 整体替换策略(线程安全)
 */
void store_file_policy(const JS::File_policy &policy)
{
    auto next = std::make_shared<const JS::File_policy>(policy);
    std::unique_lock<std::shared_mutex> lock(g_file_policy_mutex);
    g_file_policy = std::move(next);
}

// ==================== 基础工具 ====================

/*
 *@brief JS 值 -> std::string;失败时异常留在上下文中
 */
bool js_value_to_string(JSContext *ctx, JSValueConst val, std::string &out)
{
    size_t len = 0;
    const char *text = JS_ToCStringLen(ctx, &len, val);
    if (!text)
        return false;
    out.assign(text, len);
    JS_FreeCString(ctx, text);
    return true;
}

/*
 *@brief 多个 JS 实参 -> 以空格拼接的字符串(用于日志转换)
 */
bool js_args_to_string(JSContext *ctx, int argc, JSValueConst *argv, std::string &out)
{
    out.clear();
    for (int i = 0; i < argc; ++i)
    {
        std::string item;
        if (!js_value_to_string(ctx, argv[i], item))
            return false;
        if (i > 0)
            out.push_back(' ');
        out += item;
    }
    return true;
}

/*
 *@brief 读取对象属性并转成字符串;属性不存在(undefined/null)时保持 out 不变
 */
bool js_object_get_string(JSContext *ctx, JSValueConst obj, const char *key, std::string &out)
{
    JSValue val = JS_GetPropertyStr(ctx, obj, key);
    if (JS_IsException(val))
        return false;
    bool ok = true;
    if (!JS_IsUndefined(val) && !JS_IsNull(val))
        ok = js_value_to_string(ctx, val, out);
    JS_FreeValue(ctx, val);
    return ok;
}

/*
 *@brief 读取对象属性并转成整数;属性不存在时保持 out 不变
 */
bool js_object_get_int(JSContext *ctx, JSValueConst obj, const char *key, long &out)
{
    JSValue val = JS_GetPropertyStr(ctx, obj, key);
    if (JS_IsException(val))
        return false;
    bool ok = true;
    if (!JS_IsUndefined(val) && !JS_IsNull(val))
    {
        int32_t num = 0;
        if (JS_ToInt32(ctx, &num, val) < 0)
            ok = false;
        else
            out = num;
    }
    JS_FreeValue(ctx, val);
    return ok;
}

/*
 *@brief 读取对象属性并转成布尔;属性不存在时保持 out 不变
 */
bool js_object_get_bool(JSContext *ctx, JSValueConst obj, const char *key, bool &out)
{
    JSValue val = JS_GetPropertyStr(ctx, obj, key);
    if (JS_IsException(val))
        return false;
    bool ok = true;
    if (!JS_IsUndefined(val) && !JS_IsNull(val))
    {
        int flag = JS_ToBool(ctx, val);
        if (flag < 0)
            ok = false;
        else
            out = (flag != 0);
    }
    JS_FreeValue(ctx, val);
    return ok;
}

/*
 *@brief 读取整个脚本文件
 */
bool read_whole_file(const std::string &path, std::string &out)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        return false;
    std::ostringstream buffer;
    buffer << in.rdbuf();
    out = buffer.str();
    return true;
}

/*
 *@brief 日志只能单行:把换行替换成空格
 */
std::string one_line(const std::string &text)
{
    std::string out;
    out.reserve(text.size());
    for (char ch : text)
    {
        if (ch == '\r')
            continue;
        out.push_back(ch == '\n' ? ' ' : ch);
    }
    return out;
}

/*
 *@brief 取出上下文中的异常并转成文本(含 `stack` 属性)
 *@note  会清除上下文中的异常状态,可以安全地继续执行
 */
std::string js_exception_text(JSContext *ctx)
{
    std::string text;
    JSValue exc = JS_GetException(ctx);

    bool has_value = !JS_IsException(exc) && !JS_IsUndefined(exc) && !JS_IsNull(exc);
    if (has_value && !js_value_to_string(ctx, exc, text))
    {
        // 转换失败(例如内存耗尽):丢掉二次异常,退回默认文本
        JS_FreeValue(ctx, JS_GetException(ctx));
        text.clear();
    }

    if (JS_IsObject(exc))
    {
        JSValue stack = JS_GetPropertyStr(ctx, exc, "stack");
        if (!JS_IsException(stack) && !JS_IsUndefined(stack) && !JS_IsNull(stack))
        {
            std::string stack_text;
            if (js_value_to_string(ctx, stack, stack_text) && !stack_text.empty())
            {
                if (!text.empty())
                    text.push_back('\n');
                text += stack_text;
            }
        }
        JS_FreeValue(ctx, stack);
    }

    JS_FreeValue(ctx, exc);
    if (text.empty())
        text = "unknown error";
    return text;
}

/*
 *@brief 取得(必要时创建)一个全局命名对象
 *@return 对象自身的强引用,失败返回 JS_EXCEPTION
 */
JSValue js_ensure_object(JSContext *ctx, JSValueConst parent, const char *name)
{
    JSValue obj = JS_GetPropertyStr(ctx, parent, name);
    if (JS_IsException(obj))
        return obj;
    if (JS_IsObject(obj))
        return obj;

    JS_FreeValue(ctx, obj);
    obj = JS_NewObject(ctx);
    if (JS_IsException(obj))
        return obj;

    if (JS_SetPropertyStr(ctx, parent, name, JS_DupValue(ctx, obj)) < 0)
    {
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }
    return obj;
}

/*
 *@brief 在指定 runtime 上注册自定义类
 *@note  JS_NewRuntime 每次请求都会新建一个 runtime,所以每个 runtime 都要注册一次;
 *       JS_NewClassID 的计数器是进程级共享的,用互斥锁保护
 */
std::mutex g_class_mutex;

void register_class(JSRuntime *rt, JSClassID &class_id, const char *name,
                    JSClassFinalizer *finalizer)
{
    std::lock_guard<std::mutex> lock(g_class_mutex);
    if (class_id == 0)
        JS_NewClassID(&class_id);
    if (JS_IsRegisteredClass(rt, class_id))
        return;

    JSClassDef def{};
    def.class_name = name;
    def.finalizer = finalizer;
    if (JS_NewClass(rt, class_id, &def) < 0)
        Log::error(std::string("JS: failed to register class ") + name);
}

// ==================== 超时控制 ====================

/*
 *@brief 进程级超时配置
 */
std::mutex g_timeouts_mutex;
JS::Timeouts g_timeouts;

/*
 *@brief 进程级内存限制配置
 */
std::mutex g_limits_mutex;
JS::Limits g_limits;

/*
 *@class Exec_deadline
 *@brief 给一次脚本执行装上截止时间,析构时自动摘掉中断处理器
 *
 *@note  quickjs 的中断处理器只在执行字节码时被轮询,处理器只读一个原子变量,
 *       不分配内存、不抛异常;到时后 JS_Eval / JS_Call 以异常返回。
 */
class Exec_deadline
{
public:
    Exec_deadline(JSRuntime *rt, int timeout_ms): rt_(rt)
    {
        if (rt_ == nullptr || timeout_ms <= 0)
            return;

        const long long now =
            std::chrono::steady_clock::now().time_since_epoch().count();
        state_.deadline_ns.store(now + static_cast<long long>(timeout_ms) * 1000000LL,
                                 std::memory_order_relaxed);
        JS_SetInterruptHandler(rt_, &Exec_deadline::on_interrupt, &state_);
        active_ = true;
    }

    ~Exec_deadline()
    {
        if (active_)
            JS_SetInterruptHandler(rt_, nullptr, nullptr);
        state_.deadline_ns.store(0, std::memory_order_relaxed);
    }

    /*
     *@brief 是否已超过截止时间(用于把"被打断"识别成"超时")
     */
    bool expired() const
    {
        const long long deadline = state_.deadline_ns.load(std::memory_order_relaxed);
        if (deadline == 0)
            return false;
        return std::chrono::steady_clock::now().time_since_epoch().count() > deadline;
    }

    Exec_deadline() = delete;
    Exec_deadline(const Exec_deadline &) = delete;
    Exec_deadline(Exec_deadline &&) = delete;
    Exec_deadline &operator=(const Exec_deadline &) = delete;
    Exec_deadline &operator=(Exec_deadline &&) = delete;

private:
    struct State
    {
        std::atomic<long long> deadline_ns{0};
    };

    static int on_interrupt(JSRuntime *, void *opaque)
    {
        auto *state = static_cast<State *>(opaque);
        if (state == nullptr)
            return 0;
        const long long deadline = state->deadline_ns.load(std::memory_order_relaxed);
        if (deadline == 0)
            return 0;
        return std::chrono::steady_clock::now().time_since_epoch().count() > deadline
               ? 1 : 0;
    }

    JSRuntime *rt_ = nullptr;
    State state_;
    bool active_ = false;
};

/*
 *@brief 本轮执行的脚本超时(毫秒)
 */
int script_timeout_ms()
{
    std::lock_guard<std::mutex> lock(g_timeouts_mutex);
    return g_timeouts.js_exec_ms;
}

/*
 *@brief ws.recv() 的缺省超时(毫秒,0 表示一直阻塞)
 */
int websocket_recv_timeout_ms()
{
    std::lock_guard<std::mutex> lock(g_timeouts_mutex);
    return g_timeouts.websocket_recv_ms;
}

// ==================== 内存限制 ====================

/*
 *@enum Limit_kind
 *@brief 三类脚本各自的内存上限
 */
enum class Limit_kind
{
    Request,  ///< HTTP / WebSocket 业务脚本
    Security, ///< 安全检测脚本
    Global    ///< 全局数据脚本
};

/*
 *@brief 取当前配置的某类脚本内存上限(字节,0 表示不限制)
 */
std::size_t memory_limit_bytes(Limit_kind kind)
{
    std::lock_guard<std::mutex> lock(g_limits_mutex);
    switch (kind)
    {
    case Limit_kind::Security:
        return g_limits.security_bytes;
    case Limit_kind::Global:
        return g_limits.global_bytes;
    case Limit_kind::Request:
    default:
        return g_limits.request_bytes;
    }
}

/*
 *@brief 给一个新建的运行时施加内存上限
 *@note  0 表示不限制:quickjs 默认不设上限,这里直接跳过
 */
void apply_memory_limit(JSRuntime *rt, std::size_t bytes)
{
    if (rt == nullptr || bytes == 0)
        return;
    JS_SetMemoryLimit(rt, bytes);
}

/*
 *@brief 给一类脚本新建的运行时施加内存上限
 */
void apply_memory_limit(JSRuntime *rt, Limit_kind kind)
{
    apply_memory_limit(rt, memory_limit_bytes(kind));
}

// ==================== JSON 往返 ====================

/*
 *@brief JS 值 -> JSON 文本(用于跨运行时传递与全局数据存储)
 *@return false 表示值不可序列化(如函数 / undefined)或内存不足
 */
bool json_stringify(JSContext *ctx, JSValueConst value, std::string &out)
{
    JSValue text = JS_JSONStringify(ctx, value, JS_UNDEFINED, JS_UNDEFINED);
    if (JS_IsException(text))
    {
        js_exception_text(ctx); // 清掉上下文里的异常
        return false;
    }
    if (JS_IsUndefined(text))
    {
        JS_FreeValue(ctx, text);
        return false;
    }
    const bool ok = js_value_to_string(ctx, text, out);
    JS_FreeValue(ctx, text);
    return ok;
}

/*
 *@brief JSON 文本 -> JS 值(失败返回 JS_EXCEPTION)
 */
JSValue json_parse(JSContext *ctx, const std::string &text)
{
    return JS_ParseJSON(ctx, text.c_str(), text.size(), "<json>");
}

/*
 *@brief 执行脚本(全局脚本 + 清空微任务队列)
 *@param error_text 失败时写入异常文本(含堆栈)
 */
bool eval_script(JSContext *ctx, JSRuntime *rt, const std::string &path,
                 const std::string &script, std::string &error_text)
{
    // 整个执行(含微任务队列)共用一个截止时间,防止死循环卡死请求线程
    Exec_deadline deadline(rt, script_timeout_ms());

    JSValue result = JS_Eval(ctx, script.data(), script.size(), path.c_str(),
                             JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(result))
    {
        error_text = js_exception_text(ctx);
        if (deadline.expired())
            error_text = "script execution timed out (js_timeout_ms)";
        JS_FreeValue(ctx, result);
        return false;
    }
    JS_FreeValue(ctx, result);

    // Promise / queueMicrotask 中的回调:限量执行,避免死循环阻塞请求线程
    for (int i = 0; i < 1024; ++i)
    {
        JSContext *job_ctx = nullptr;
        const int rc = JS_ExecutePendingJob(rt, &job_ctx);
        if (rc == 0)
            break;
        if (rc < 0)
        {
            error_text = js_exception_text(job_ctx ? job_ctx : ctx);
            if (deadline.expired())
                error_text = "script execution timed out (js_timeout_ms)";
            return false;
        }
    }
    return true;
}

// ==================== 文件路径解析 ====================

/*
 *@enum File_access
 *@brief 文件访问方向(用于权限检查)
 */
enum class File_access
{
    Read,
    Write
};

/*
 *@brief 路径分量的小写化(仅处理 ASCII,Windows 路径不区分大小写)
 */
void lower_in_place(std::filesystem::path::string_type &text)
{
    using char_type = std::filesystem::path::value_type;
    for (char_type &ch : text)
    {
        if (ch >= static_cast<char_type>('A') && ch <= static_cast<char_type>('Z'))
        {
            ch = static_cast<char_type>(ch - static_cast<char_type>('A') +
                                        static_cast<char_type>('a'));
        }
    }
}

/*
 *@brief 判断 target 是否位于 root 之内(逐段比较,忽略大小写)
 *@note  必须以路径分量比较,不能用字符串前缀:
 *       `C:\\data2` 不能被认为是 `C:\\data` 的子路径
 */
bool path_within_root(const std::filesystem::path &root, const std::filesystem::path &target)
{
    const std::filesystem::path norm_root = root.lexically_normal();
    const std::filesystem::path norm_target = target.lexically_normal();

    auto it_root = norm_root.begin();
    auto it_target = norm_target.begin();

    for (; it_root != norm_root.end(); ++it_root)
    {
        // 尾部分隔符会迭代出空分量,直接跳过
        if (it_root->empty())
            continue;
        while (it_target != norm_target.end() && it_target->empty())
            ++it_target;
        if (it_target == norm_target.end())
            return false;

        std::filesystem::path::string_type left = it_root->native();
        std::filesystem::path::string_type right = it_target->native();
        lower_in_place(left);
        lower_in_place(right);
        if (left != right)
            return false;
        ++it_target;
    }
    return true;
}

/*
 *@brief ASCII 小写化(规则和脚本路径统一按小写比较)
 */
std::string lower_copy(const std::string &text)
{
    std::string out(text);
    for (char &ch : out)
    {
        if (ch >= 'A' && ch <= 'Z')
            ch = static_cast<char>(ch - 'A' + 'a');
    }
    return out;
}

/*
 *@brief 通配匹配:`*` 不跨目录,`**` 跨目录,`?` 匹配单个非分隔符字符
 *@param pattern 规则里的模式(已小写、以 / 分隔)
 *@param text 脚本相对路径(已小写、以 / 分隔)
 */
bool glob_match(const std::string &pattern, const std::string &text)
{
    const std::size_t n = pattern.size();
    const std::size_t m = text.size();
    if (n == 0)
        return m == 0;

    // dp[i][j]: pattern[0..i) 能否匹配 text[0..j)
    // 用一块连续内存存表:每次匹配只做一次分配(旧实现是 n+1 次 vector 分配)
    const std::size_t stride = m + 1;
    std::vector<char> dp((n + 1) * stride, 0);
    auto at = [&](std::size_t i, std::size_t j) -> char &
    {
        return dp[i * stride + j];
    };
    at(0, 0) = 1;

    for (std::size_t i = 0; i < n; ++i)
    {
        const bool double_star =
            pattern[i] == '*' && i + 1 < n && pattern[i + 1] == '*';
        const bool single_star = pattern[i] == '*' && !double_star;

        for (std::size_t j = 0; j <= m; ++j)
        {
            if (at(i, j) == 0)
                continue;

            if (double_star)
            {
                at(i + 2, j) = 1; // ** 匹配空串
                if (j < m)
                    at(i, j + 1) = 1; // ** 吃一个字符(含 /)
            }
            else if (single_star)
            {
                at(i + 1, j) = 1; // * 匹配空串
                if (j < m && text[j] != '/')
                    at(i, j + 1) = 1; // * 吃一个非 / 字符
            }
            else if (j < m && (pattern[i] == '?' ? text[j] != '/' : pattern[i] == text[j]))
            {
                at(i + 1, j + 1) = 1;
            }
        }
    }
    return at(n, m) != 0;
}

/*
 *@brief 模式/脚本路径规范化:统一分隔符、去掉开头的 / 与 ./,转小写
 */
std::string normalize_script_text(const std::string &text)
{
    std::string out;
    out.reserve(text.size());
    for (char ch : text)
        out.push_back(ch == '\\' ? '/' : ch);
    while (!out.empty() && out[0] == '/')
        out.erase(0, 1);
    while (out.size() >= 2 && out[0] == '.' && out[1] == '/')
        out.erase(0, 2);
    return lower_copy(out);
}

/*
 *@brief 绝对路径的规范化:统一 '/'、保留开头的 /(或盘符)、转小写
 *@note  和 normalize_script_text 的区别:这里**不能**去掉开头的 '/',
 *       否则 POSIX 下绝对路径会退化成相对路径,导致 full_access 脚本匹配失败
 */
std::string normalize_abs_text(const std::string &text)
{
    std::string out;
    out.reserve(text.size());
    for (char ch : text)
        out.push_back(ch == '\\' ? '/' : ch);
    return lower_copy(out);
}

/*
 *@struct Script_key_cache
 *@brief 脚本相对路径缓存(每个线程一份)
 *
 *@note  一次脚本执行期间 t_current_script 和 script_dir 都不会变,而 File.* 可能被
 *       脚本调用很多次;这里把上次算出的相对路径缓存住,免得每次都做 canonical
 *       查询(那是好几次文件系统调用,高并发下很贵)。
 */
struct Script_key_cache
{
    std::string script;     ///< 缓存对应的脚本路径
    std::string script_dir; ///< 缓存对应的脚本目录
    std::string key;        ///< 上次算出的相对路径(空表示脚本不在目录内)
    bool ready = false;     ///< 缓存是否有效
};

thread_local Script_key_cache t_script_key;

/*
 *@brief 当前脚本相对脚本目录的路径,用于匹配规则;失败返回空串(后续一律拒绝)
 */
std::string current_script_key(const JS::File_policy &policy)
{
    if (t_current_script.empty() || policy.script_dir.empty())
        return std::string();

    if (t_script_key.ready && t_script_key.script == t_current_script &&
            t_script_key.script_dir == policy.script_dir)
    {
        return t_script_key.key;
    }

    // 重新计算(结果可能为空:脚本不在脚本目录内,按拒绝处理)
    std::string key;
    std::error_code ec;
    const std::filesystem::path script =
        std::filesystem::weakly_canonical(std::filesystem::u8path(t_current_script), ec);
    if (!ec && !script.empty())
    {
        const std::filesystem::path root = std::filesystem::u8path(policy.script_dir);
        if (path_within_root(root, script))
        {
            const std::filesystem::path rel = script.lexically_relative(root);
            if (!rel.empty())
                key = normalize_script_text(rel.generic_u8string());
        }
    }

    t_script_key.script = t_current_script;
    t_script_key.script_dir = policy.script_dir;
    t_script_key.key = key;
    t_script_key.ready = true;
    return key;
}

/*
 *@brief 当前脚本的规范化绝对路径(小写、'/' 分隔)
 *@note  用于匹配 File_policy::full_access_scripts;规范化失败时退化成弱规范化结果
 */
std::string current_script_abs()
{
    if (t_current_script.empty())
        return std::string();

    const std::filesystem::path given = std::filesystem::u8path(t_current_script);
    std::error_code ec;
    const std::filesystem::path script = std::filesystem::weakly_canonical(given, ec);
    if (ec || script.empty())
        return normalize_abs_text(given.lexically_normal().generic_u8string());

    return normalize_abs_text(script.generic_u8string());
}

/*
 *@brief 当前脚本是否拥有"完全文件 / SQL 访问"权限
 *@note  默认关闭:只有配置文件里显式指定的脚本才会命中 full_access_scripts,
 *       未命中的脚本仍然走 js_read_rule / js_write_rule 的目录白名单
 */
bool script_has_full_access(const JS::File_policy &policy)
{
    if (policy.full_access_scripts.empty())
        return false;

    const std::string current = current_script_abs();
    if (current.empty())
        return false;

    for (const std::string &script : policy.full_access_scripts)
    {
        if (script == current)
            return true;
    }
    return false;
}

/*
 *@brief 为当前脚本挑一条规则
 *@note  优先级:精确匹配 > 其它通配规则(按书写顺序) > '*' / '**' 兜底,
 *       这样 --file-root 设置的兜底规则不会抢走具体脚本的规则
 */
const JS::File_rule *match_script_rule(const JS::File_policy &policy, const std::string &key)
{
    if (key.empty())
        return nullptr;

    for (const JS::File_rule &rule : policy.rules)
    {
        if (rule.script == key)
            return &rule;
    }

    for (const JS::File_rule &rule : policy.rules)
    {
        if (rule.script == "*" || rule.script == "**")
            continue;
        if (glob_match(rule.script, key))
            return &rule;
    }

    for (const JS::File_rule &rule : policy.rules)
    {
        if (rule.script == "*" || rule.script == "**")
            return &rule;
    }
    return nullptr;
}

/*
 *@brief 当前脚本对应的规则(没命中时返回 nullptr)
 */
const JS::File_rule *current_file_rule(const JS::File_policy &policy)
{
    return match_script_rule(policy, current_script_key(policy));
}

/*
 *@brief 为当前脚本挑一条 SQL 规则
 *@note  优先级与文件规则一致:脚本相对路径精确匹配 > 绝对路径精确匹配 >
 *       其它通配规则(按书写顺序) > '*' / '**' 兜底
 */
const JS::Sql_rule *match_sql_rule(const JS::File_policy &policy, const std::string &key,
                                   const std::string &abs)
{
    for (const JS::Sql_rule &rule : policy.sql_rules)
    {
        if (rule.script.empty())
            continue;
        if ((!key.empty() && rule.script == key) || rule.script == abs)
            return &rule;
    }

    for (const JS::Sql_rule &rule : policy.sql_rules)
    {
        if (rule.script == "*" || rule.script == "**")
            continue;
        if ((!key.empty() && glob_match(rule.script, key)) || glob_match(rule.script, abs))
            return &rule;
    }

    for (const JS::Sql_rule &rule : policy.sql_rules)
    {
        if (rule.script == "*" || rule.script == "**")
            return &rule;
    }
    return nullptr;
}

/*
 *@brief 数据库路径是否命中允许列表(精确路径或通配模式)
 */
bool db_pattern_match(const std::vector<std::string> &patterns, const std::string &target)
{
    for (const std::string &pattern : patterns)
    {
        if (pattern.empty())
            continue;
        if (pattern == target || glob_match(pattern, target))
            return true;
    }
    return false;
}

/*
 *@brief 解析 SQLite 打开路径并校验权限
 *@param readonly 是否以只读方式打开
 *@param full_access 输出:是否走了"完全访问"分支
 *@note  失败时在上下文中抛出异常并返回 false;未授权一律拒绝(默认拒绝)
 */
bool resolve_sql_path(JSContext *ctx, const JS::File_policy &policy, const std::string &raw,
                      bool readonly, std::filesystem::path &out, bool &full_access)
{
    full_access = false;
    if (raw.empty())
    {
        JS_ThrowTypeError(ctx, "database path is required");
        return false;
    }

    const std::filesystem::path given = std::filesystem::u8path(raw);
    std::error_code ec;
    std::filesystem::path target;
    if (given.is_absolute())
    {
        target = std::filesystem::weakly_canonical(given, ec);
    }
    else
    {
        std::filesystem::path base;
        if (!policy.script_dir.empty())
            base = std::filesystem::u8path(policy.script_dir);
        else
            base = std::filesystem::current_path(ec);
        target = std::filesystem::weakly_canonical(base / given, ec);
    }
    if (ec || target.empty())
    {
        JS_ThrowTypeError(ctx, "invalid database path");
        return false;
    }

    // 被授予完全访问权限的脚本:数据库位置不做限制
    if (script_has_full_access(policy))
    {
        out = target;
        full_access = true;
        return true;
    }

    const std::string key = current_script_key(policy);
    const std::string abs = current_script_abs();
    const JS::Sql_rule *rule = match_sql_rule(policy, key, abs);
    if (rule == nullptr)
    {
        Log::warning("JS: sqlite denied, no rule for script: " +
                     (key.empty() ? t_current_script : key));
        JS_ThrowTypeError(ctx, "sqlite access is not allowed for this script");
        return false;
    }

    const std::string db_key = lower_copy(target.lexically_normal().generic_u8string());
    const bool can_write = db_pattern_match(rule->write_dbs, db_key);
    const bool can_read = can_write || db_pattern_match(rule->read_dbs, db_key);
    if (!can_read)
    {
        Log::warning("JS: sqlite denied, database outside allowed list: " + db_key +
                     " (script: " + (key.empty() ? abs : key) + ")");
        JS_ThrowTypeError(ctx, "database is not allowed for this script");
        return false;
    }
    if (!readonly && !can_write)
    {
        Log::warning("JS: sqlite write denied, database is read-only: " + db_key);
        JS_ThrowTypeError(ctx, "database is read-only for this script");
        return false;
    }

    out = target;
    return true;
}

/*
 *@brief 记录当前请求正在执行的脚本,供 File.* 匹配规则
 */
void set_current_script(const std::string &path)
{
    t_current_script = path;
    t_script_key = Script_key_cache(); // 换了脚本,缓存作废
}

/*
 *@class Scoped_script
 *@brief 在当前线程临时切换"正在执行的脚本",离开作用域时恢复之前的脚本
 *
 *@note  脚本执行期间是可以同步进入另一个脚本的:业务脚本调用 Global.call
 *       时,Global.call 会在同一个线程里运行全局脚本。如果切换后不恢复,
 *       返回业务脚本后 t_current_script 仍停在全局脚本上,后续 File.* /
 *       Sqlite.open 就会按全局脚本的权限规则匹配 —— 全局脚本通常被授予
 *       更大的文件 / 数据库权限,等于业务脚本借 Global.call 提权。
 *       所有"切换当前脚本"的地方都必须用本类,保证权限上下文随作用域复原。
 */
class Scoped_script
{
public:
    explicit Scoped_script(const std::string &path) : previous_(t_current_script)
    {
        set_current_script(path);
    }

    ~Scoped_script()
    {
        set_current_script(previous_);
    }

    Scoped_script() = delete;
    Scoped_script(const Scoped_script &) = delete;
    Scoped_script(Scoped_script &&) = delete;
    Scoped_script &operator=(const Scoped_script &) = delete;
    Scoped_script &operator=(Scoped_script &&) = delete;

private:
    std::string previous_;
};

/*
 *@brief 把脚本传入的路径解析成受规则约束的绝对路径
 *@param policy 本次操作用的策略快照(由调用方一次性取好,线程安全)
 *@param access 本次访问的方向(读/写),据此选择读目录或写目录
 *@note  失败时会在上下文中抛出异常并返回 false。
 *       路径统一按"相对脚本目录(--dir)"解释,所有脚本共用一套路径命名空间;
 *       只接受相对路径:绝对路径、盘符路径、含 `..` 的路径直接拒绝;
 *       解析后再做 canonical 化,并确认结果落在允许的目录里(符号链接也算在内)。
 */
bool resolve_file_path(JSContext *ctx, const JS::File_policy &policy, const std::string &raw,
                       File_access access, std::filesystem::path &out)
{
    // 完全访问脚本:不做任何目录限制(允许绝对路径、盘符路径与 ..)
    if (script_has_full_access(policy))
    {
        if (raw.empty())
        {
            JS_ThrowTypeError(ctx, "file path is required");
            return false;
        }

        const std::filesystem::path given = std::filesystem::u8path(raw);
        std::error_code ec;
        std::filesystem::path target;
        if (given.is_absolute())
        {
            target = std::filesystem::weakly_canonical(given, ec);
        }
        else
        {
            const std::filesystem::path base =
                policy.script_dir.empty() ? std::filesystem::current_path(ec)
                : std::filesystem::u8path(policy.script_dir);
            target = std::filesystem::weakly_canonical(base / given, ec);
        }
        if (ec || target.empty())
        {
            JS_ThrowTypeError(ctx, "invalid file path");
            return false;
        }
        out = target;
        return true;
    }

    if (policy.rules.empty())
    {
        JS_ThrowTypeError(ctx, "file access is disabled");
        return false;
    }

    const std::string key = current_script_key(policy);
    const JS::File_rule *rule = match_script_rule(policy, key);
    if (rule == nullptr)
    {
        // 没配规则的脚本一律拒绝(默认拒绝,而不是默认放行)
        Log::warning("JS: file access denied, no rule for script: " +
                     (key.empty() ? t_current_script : key));
        JS_ThrowTypeError(ctx, "file access is not allowed for this script");
        return false;
    }

    const std::vector<std::string> &dirs =
        (access == File_access::Read) ? rule->read_dirs : rule->write_dirs;
    if (dirs.empty())
    {
        JS_ThrowTypeError(ctx, (access == File_access::Read)
                          ? "file reading is disabled for this script"
                          : "file writing is disabled for this script");
        return false;
    }
    if (raw.empty())
    {
        JS_ThrowTypeError(ctx, "file path is required");
        return false;
    }
    if (policy.script_dir.empty())
    {
        JS_ThrowTypeError(ctx, "file access is disabled (script dir is unknown)");
        return false;
    }

    // 脚本传进来的是 UTF-8 字符串,必须经 u8path 转成宽路径,
    // 否则中文路径在 Windows 上会乱码
    const std::filesystem::path given = std::filesystem::u8path(raw);

    // 绝对路径一律拒绝:否则 (脚本目录 / given) 会直接变成 given 本身
    if (given.has_root_name() || given.has_root_directory())
    {
        Log::warning("JS: absolute file path denied: " + raw + " (script: " + key + ")");
        JS_ThrowTypeError(ctx, "file path must be relative");
        return false;
    }
    // 逐段检查:出现 `..` 直接拒绝(不做规范化,避免靠写法蒙混过关)
    for (const std::filesystem::path &part : given)
    {
        if (part == std::filesystem::path(".."))
        {
            Log::warning("JS: file path with '..' denied: " + raw +
                         " (script: " + key + ")");
            JS_ThrowTypeError(ctx, "file path must not contain '..'");
            return false;
        }
    }

    // 以脚本目录为基准解析路径
    const std::filesystem::path base = std::filesystem::u8path(policy.script_dir);
    std::error_code ec;
    // weakly_canonical:目标不存在时也能规范化(用于写入新文件),
    // 同时会消解符号链接,避免从目录里绕出去
    const std::filesystem::path target = std::filesystem::weakly_canonical(base / given, ec);
    if (ec || target.empty())
    {
        JS_ThrowTypeError(ctx, "invalid file path");
        return false;
    }

    // 解析结果必须落在允许的目录里
    for (const std::string &dir_text : dirs)
    {
        if (path_within_root(std::filesystem::u8path(dir_text), target))
        {
            out = target;
            return true;
        }
    }

    // 越界访问要留痕:这类尝试往往意味着脚本被注入
    Log::warning("JS: file access denied, path outside allowed directories: " + raw +
                 " (script: " + key + ")");
    JS_ThrowTypeError(ctx, "file path is outside the allowed directories");
    return false;
}

// ==================== 文件并发保护(多线程读写) ====================

/*
 *@class 按路径分片的读写锁
 *
 *@note  并发语义(同一进程内):
 *         - 同一路径的读(read / readText / exists / size / list / send.file)可以并行;
 *         - 同一路径的写(write / append / remove / mkdir)独占,与任何读 / 写互斥,
 *           因此 write 的 "清空 + 写满" 不会被另一个线程插进来,
 *           读也不会读到写了一半的文件;
 *         - 每次操作只取一把分片锁(不做嵌套),所以不会死锁;
 *         - 分片数是固定的,锁对象不会随访问过的路径数量增长。
 *       不同路径偶尔哈希到同一分片只会让它们暂时串行,不影响正确性。
 */
constexpr std::size_t FILE_LOCK_SHARDS = 64u;

std::array<std::shared_mutex, FILE_LOCK_SHARDS> g_file_locks; ///< 路径分片读写锁

/*
 *@brief 路径 -> 分片索引(规范化 + 小写,同一文件的不同写法落到同一分片)
 */
std::size_t file_lock_shard(const std::filesystem::path &path)
{
    const std::string key = lower_copy(path.lexically_normal().generic_u8string());
    return std::hash<std::string> {}(key) % FILE_LOCK_SHARDS;
}

/*
 *@brief 取读锁(共享):同一路径的多个读可以并发
 */
std::shared_lock<std::shared_mutex> file_read_lock(const std::filesystem::path &path)
{
    return std::shared_lock<std::shared_mutex>(g_file_locks[file_lock_shard(path)]);
}

/*
 *@brief 取写锁(独占):与同一路径的所有读写互斥
 */
std::unique_lock<std::shared_mutex> file_write_lock(const std::filesystem::path &path)
{
    return std::unique_lock<std::shared_mutex>(g_file_locks[file_lock_shard(path)]);
}

// ==================== 二进制数据 ====================

/*
 *@brief JS 值 -> 原始字节:字符串 / Uint8Array 等 TypedArray / ArrayBuffer
 *@note  失败时会在上下文中抛出异常
 */
bool js_value_to_bytes(JSContext *ctx, JSValueConst val, std::string &out)
{
    size_t byte_offset = 0;
    size_t byte_length = 0;
    size_t element_size = 0;
    JSValue holder =
        JS_GetTypedArrayBuffer(ctx, val, &byte_offset, &byte_length, &element_size);
    if (!JS_IsException(holder))
    {
        size_t size = 0;
        uint8_t *data = JS_GetArrayBuffer(ctx, &size, holder);
        const bool inside = (data != nullptr) && (byte_offset + byte_length <= size);
        if (inside)
        {
            out.assign(reinterpret_cast<const char *>(data) + byte_offset, byte_length);
        }
        JS_FreeValue(ctx, holder);
        if (!inside)
        {
            JS_ThrowTypeError(ctx, "cannot read the underlying ArrayBuffer");
            return false;
        }
        return true;
    }
    // 不是 TypedArray:清掉异常,继续按 ArrayBuffer / 字符串尝试
    JS_FreeValue(ctx, JS_GetException(ctx));

    size_t size = 0;
    uint8_t *data = JS_GetArrayBuffer(ctx, &size, val);
    if (data != nullptr)
    {
        out.assign(reinterpret_cast<const char *>(data), size);
        return true;
    }
    JS_FreeValue(ctx, JS_GetException(ctx));

    if (JS_IsString(val))
        return js_value_to_string(ctx, val, out);

    JS_ThrowTypeError(ctx, "binary data expected (string, Uint8Array or ArrayBuffer)");
    return false;
}

/*
 *@brief 原始字节 -> Uint8Array(复制一份,与 C++ 侧的缓冲区解耦)
 */
JSValue js_new_bytes(JSContext *ctx, const std::string &data)
{
    // 注意:先按长度构造 TypedArray 再把字节拷进去。
    // 当前 quickjs 版本在 C 层用 ArrayBuffer 参数构造 Uint8Array 会得到
    // 长度为 0 的数组(JS 层 new Uint8Array(buffer) 则正常),故不能走那条路。
    JSValue length = JS_NewInt64(ctx, static_cast<int64_t>(data.size()));
    if (JS_IsException(length))
        return length;

    JSValue array = JS_NewTypedArray(ctx, 1, &length, JS_TYPED_ARRAY_UINT8);
    JS_FreeValue(ctx, length);
    if (JS_IsException(array))
        return array;

    if (!data.empty())
    {
        size_t byte_offset = 0;
        size_t byte_length = 0;
        size_t element_size = 0;
        JSValue holder =
            JS_GetTypedArrayBuffer(ctx, array, &byte_offset, &byte_length, &element_size);
        if (JS_IsException(holder))
        {
            JS_FreeValue(ctx, array);
            return holder;
        }

        size_t buffer_size = 0;
        uint8_t *raw = JS_GetArrayBuffer(ctx, &buffer_size, holder);
        if (raw == nullptr || byte_offset + data.size() > buffer_size)
        {
            JS_FreeValue(ctx, holder);
            JS_FreeValue(ctx, array);
            return JS_ThrowInternalError(ctx, "cannot fill byte array");
        }
        std::memcpy(raw + byte_offset, data.data(), data.size());
        JS_FreeValue(ctx, holder);
    }

    return array;
}

// ==================== 文件接口(全局对象 File) ====================

/*
 *@brief 根据扩展名猜测 Content-Type(未知类型按二进制处理)
 */
std::string guess_content_type(const std::filesystem::path &path)
{
    const std::filesystem::path::string_type native_ext = path.extension().native();
    std::string ext;
    ext.reserve(native_ext.size());
    for (std::filesystem::path::value_type ch : native_ext)
    {
        if (ch > 0x7f)
        {
            // 非 ASCII 扩展名:不做猜测
            ext.clear();
            break;
        }
        char narrow = static_cast<char>(ch);
        if (narrow >= 'A' && narrow <= 'Z')
            narrow = static_cast<char>(narrow - 'A' + 'a');
        ext.push_back(narrow);
    }

    static const std::map<std::string, std::string> table = {
        {".html", "text/html; charset=utf-8"},
        {".htm", "text/html; charset=utf-8"},
        {".js", "text/javascript; charset=utf-8"},
        {".mjs", "text/javascript; charset=utf-8"},
        {".css", "text/css; charset=utf-8"},
        {".json", "application/json; charset=utf-8"},
        {".txt", "text/plain; charset=utf-8"},
        {".csv", "text/csv; charset=utf-8"},
        {".xml", "application/xml; charset=utf-8"},
        {".svg", "image/svg+xml"},
        {".png", "image/png"},
        {".jpg", "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".gif", "image/gif"},
        {".webp", "image/webp"},
        {".ico", "image/x-icon"},
        {".bmp", "image/bmp"},
        {".pdf", "application/pdf"},
        {".wasm", "application/wasm"},
        {".mp3", "audio/mpeg"},
        {".mp4", "video/mp4"},
        {".webm", "video/webm"},
        {".woff", "font/woff"},
        {".woff2", "font/woff2"},
        {".ttf", "font/ttf"},
        {".zip", "application/zip"},
        {".gz", "application/gzip"},
        {".bin", "application/octet-stream"},
    };

    const auto it = table.find(ext);
    return it == table.end() ? std::string("application/octet-stream") : it->second;
}

/*
 *@brief 解析第一个路径实参
 *@param policy 本次操作用的策略快照
 */
bool file_arg_path(JSContext *ctx, const JS::File_policy &policy, JSValueConst arg,
                   File_access access, std::filesystem::path &out)
{
    std::string raw;
    if (!js_value_to_string(ctx, arg, raw))
        return false;
    return resolve_file_path(ctx, policy, raw, access, out);
}

/*
 *@brief File.read / File.readText 的公共实现
 *@param start_value 起始偏移(字节;负数表示从文件末尾倒数;缺省 0)
 *@param end_value   结束位置,不含(负数表示从文件末尾倒数;缺省为文件末尾)
 *@note  先按 [start,end) 截取,再校验 max_read_size,所以大文件可以分块读取;
 *       越界按 Python 切片的习惯自动截断到 [0,size]
 */
JSValue file_read_impl(JSContext *ctx, JSValueConst arg, bool as_text,
                       JSValueConst start_value, JSValueConst end_value)
{
    int64_t start = 0;
    int64_t end = 0;
    const bool has_start = !JS_IsUndefined(start_value) && !JS_IsNull(start_value);
    const bool has_end = !JS_IsUndefined(end_value) && !JS_IsNull(end_value);

    if (has_start && JS_ToInt64(ctx, &start, start_value) < 0)
    {
        js_exception_text(ctx);
        return JS_ThrowTypeError(ctx, "File.read: start must be an integer");
    }
    if (has_end && JS_ToInt64(ctx, &end, end_value) < 0)
    {
        js_exception_text(ctx);
        return JS_ThrowTypeError(ctx, "File.read: end must be an integer");
    }

    const auto policy = file_policy_snapshot();

    std::filesystem::path target;
    if (!file_arg_path(ctx, *policy, arg, File_access::Read, target))
        return JS_EXCEPTION;

    // 读锁:同一文件的多个读可以并行,但不会读到正在被写入的内容
    const auto lock = file_read_lock(target);

    std::error_code ec;
    const auto size_raw = std::filesystem::file_size(target, ec);
    if (ec)
        return JS_ThrowTypeError(ctx, "cannot stat file");

    const int64_t size = static_cast<int64_t>(size_raw);

    // 负数从末尾倒数;越界截断,保证 from / to 落在 [0,size]
    int64_t from = has_start ? start : 0;
    int64_t to = has_end ? end : size;
    if (from < 0)
        from += size;
    if (to < 0)
        to += size;

    // start / end 同时给出且 end < start:视为非法参数直接报错,
    // 否则会静默返回空字节,把脚本里的下标错误掩盖掉
    if (has_start && has_end && to < from)
        return JS_ThrowRangeError(ctx, "File.read: end must not be less than start");

    if (from < 0)
        from = 0;
    if (from > size)
        from = size;
    if (to < from)
        to = from;
    if (to > size)
        to = size;

    // 只校验真正要读的窗口大小:整文件超限但窗口合法时仍然可读
    const int64_t count = to - from;
    if (policy->max_read_size > 0 && count > static_cast<int64_t>(policy->max_read_size))
    {
        const std::string count_text = std::to_string(count);
        const std::string limit = std::to_string(policy->max_read_size);
        return JS_ThrowInternalError(
                   ctx, "read range too large (%s bytes, limit %s bytes)",
                   count_text.c_str(), limit.c_str());
    }

    std::ifstream in(target, std::ios::binary);
    if (!in)
        return JS_ThrowTypeError(ctx, "cannot open file for reading");

    if (from > 0)
    {
        in.seekg(static_cast<std::streamoff>(from), std::ios::beg);
        if (!in)
            return JS_ThrowTypeError(ctx, "cannot seek in file");
    }

    std::string data(static_cast<std::size_t>(count), '\0');
    if (count > 0)
    {
        in.read(data.data(), static_cast<std::streamsize>(count));
        if (static_cast<std::size_t>(in.gcount()) != static_cast<std::size_t>(count))
            return JS_ThrowTypeError(ctx, "cannot read the requested range");
    }

    if (as_text)
        return JS_NewStringLen(ctx, data.c_str(), data.size());
    return js_new_bytes(ctx, data);
}

JSValue file_js_read(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "File.read(path, start?, end?) requires a path");
    return file_read_impl(ctx, argv[0], false, argc > 1 ? argv[1] : JS_UNDEFINED,
                          argc > 2 ? argv[2] : JS_UNDEFINED);
}

JSValue file_js_read_text(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "File.readText(path, start?, end?) requires a path");
    return file_read_impl(ctx, argv[0], true, argc > 1 ? argv[1] : JS_UNDEFINED,
                          argc > 2 ? argv[2] : JS_UNDEFINED);
}

/*
 *@brief File.getline(path, index?) 的实现:读文件的第 index 行(从 0 开始)
 *@param index 行号(按 Number 截断取整;截断后为负抛 RangeError,越界返回 null)
 *@return 读到的整行(不含行尾的 \r\n / \n);行号越界或文件为空返回 null
 *@note  逐行跳到目标行,内存只占一行,不会把整个文件读进来;
 *       空行返回空串而不是 null,所以"是否还有下一行"要看返回值是否为 null;
 *       文件大于 max_read_size 时改成边读边校验:超长单行立即报错,
 *       不会先为它分配巨量内存(与 File.read 先校验再分配的做法一致);
 *       读锁与 File.read 共用,不会读到正在被写入的内容
 */
JSValue file_js_getline(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "File.getline(path, index?) requires a path");

    int64_t index = 0;
    if (argc > 1 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1]))
    {
        // 与 JS 的切片习惯一致:"3" 变成 3,NaN 变成 0,小数向零截断,true 变成 1
        if (JS_ToInt64(ctx, &index, argv[1]) < 0)
        {
            // Symbol / BigInt 之类根本转不成数字:保留"索引不合法"的 TypeError
            js_exception_text(ctx);
            return JS_ThrowTypeError(ctx, "File.getline: index must be a number");
        }
        if (index < 0)
            return JS_ThrowRangeError(ctx, "File.getline: index must not be negative");
    }

    const auto policy = file_policy_snapshot();

    std::filesystem::path target;
    if (!file_arg_path(ctx, *policy, argv[0], File_access::Read, target))
        return JS_EXCEPTION;

    // 读锁:与 File.read 共用,写操作不会插进来
    const auto lock = file_read_lock(target);

    std::ifstream in(target, std::ios::binary);
    if (!in.is_open())
        return JS_ThrowTypeError(ctx, "cannot open file for reading");

    // 只有"文件本身可能藏着一行超限内容"时才需要边读边校验
    bool need_bounded = false;
    if (policy->max_read_size > 0)
    {
        std::error_code size_ec;
        const auto file_size = std::filesystem::file_size(target, size_ec);
        need_bounded = static_cast<bool>(size_ec) || file_size > policy->max_read_size;
    }

    std::string line;
    if (!need_bounded)
    {
        // 整个文件都不超过上限,任何一行都不可能超限,直接用带缓冲的方式跳行
        for (int64_t i = 0; i <= index; ++i)
        {
            if (!JS::getline(in, line))
                return JS_NULL; // 行号越界
        }
        return JS_NewStringLen(ctx, line.c_str(), line.size());
    }

    // 大文件:只把目标行留在内存里,跳过的行边读边丢
    const std::size_t limit = policy->max_read_size;
    for (int64_t i = 0; i <= index; ++i)
    {
        const bool keep = (i == index);
        if (keep)
            line.clear();

        bool has_char = false;
        for (;;)
        {
            const int ch = in.get();
            if (ch == std::char_traits<char>::eof())
            {
                if (!has_char)
                    return JS_NULL; // 目标行不存在:文件在读它之前就结束了
                break;             // 最后一行没有换行符
            }
            has_char = true;
            if (ch == '\n')
                break;
            if (!keep)
                continue;
            if (line.size() >= limit)
            {
                const std::string limit_text = std::to_string(limit);
                return JS_ThrowInternalError(ctx, "line too long (limit %s bytes)",
                                             limit_text.c_str());
            }
            line.push_back(static_cast<char>(ch));
        }

        if (keep)
            break;
    }

    // 大文件路径是逐字符读的,\r 会留在行尾,和 JS::getline 一样在这里去掉
    if (!line.empty() && line.back() == '\r')
        line.pop_back();
    return JS_NewStringLen(ctx, line.c_str(), line.size());
}

/*
 *@brief File.write / File.append 的公共实现
 */
JSValue file_write_impl(JSContext *ctx, int argc, JSValueConst *argv, bool append)
{
    if (argc < 2)
    {
        return JS_ThrowTypeError(ctx, append ? "File.append(path, data) requires data"
                                 : "File.write(path, data) requires data");
    }

    const auto policy = file_policy_snapshot();

    std::filesystem::path target;
    if (!file_arg_path(ctx, *policy, argv[0], File_access::Write, target))
        return JS_EXCEPTION;

    std::string data;
    if (!js_value_to_bytes(ctx, argv[1], data))
        return JS_EXCEPTION;

    // 写锁:同一路径的 write / append / remove / mkdir 串行执行,
    // 避免两个线程同时 truncate + 写导致内容交错
    const auto lock = file_write_lock(target);

    const std::filesystem::path parent = target.parent_path();
    if (!parent.empty())
    {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
        // 并发下 create_directories 可能因为"已经被另一个线程建好"而报错,
        // 只要最终确实存在这个目录就继续
        if (ec && !std::filesystem::is_directory(parent, ec))
            return JS_ThrowTypeError(ctx, "cannot create the parent directory");
    }

    std::ofstream out(target, std::ios::binary |
                      (append ? std::ios::app : std::ios::trunc));
    if (!out)
        return JS_ThrowTypeError(ctx, "cannot open file for writing");
    if (!data.empty())
        out.write(data.data(), static_cast<std::streamsize>(data.size()));
    out.close();
    if (!out)
        return JS_ThrowTypeError(ctx, "cannot write file");

    return JS_NewInt64(ctx, static_cast<int64_t>(data.size()));
}

JSValue file_js_write(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    return file_write_impl(ctx, argc, argv, false);
}

JSValue file_js_append(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    return file_write_impl(ctx, argc, argv, true);
}

JSValue file_js_exists(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "File.exists(path) requires a path");

    const auto policy = file_policy_snapshot();

    std::filesystem::path target;
    if (!file_arg_path(ctx, *policy, argv[0], File_access::Read, target))
        return JS_EXCEPTION;

    // 读锁:與 remove / mkdir 等写操作互斥,拿到的是稳定的结果
    const auto lock = file_read_lock(target);

    std::error_code ec;
    const bool found = std::filesystem::exists(target, ec);
    return JS_NewBool(ctx, found && !ec);
}

JSValue file_js_size(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "File.size(path) requires a path");

    const auto policy = file_policy_snapshot();

    std::filesystem::path target;
    if (!file_arg_path(ctx, *policy, argv[0], File_access::Read, target))
        return JS_EXCEPTION;

    const auto lock = file_read_lock(target);

    std::error_code ec;
    const auto size = std::filesystem::file_size(target, ec);
    if (ec)
        return JS_NewInt64(ctx, -1);
    return JS_NewInt64(ctx, static_cast<int64_t>(size));
}

JSValue file_js_list(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    const auto policy = file_policy_snapshot();

    std::filesystem::path target;
    if (argc >= 1 && !JS_IsUndefined(argv[0]) && !JS_IsNull(argv[0]))
    {
        if (!file_arg_path(ctx, *policy, argv[0], File_access::Read, target))
            return JS_EXCEPTION;
    }
    else
    {
        // 不传参时:完全访问脚本列出脚本目录,其它脚本列出第一条读目录
        if (script_has_full_access(*policy))
        {
            std::error_code ec;
            const std::filesystem::path base =
                policy->script_dir.empty() ? std::filesystem::current_path(ec)
                : std::filesystem::u8path(policy->script_dir);
            if (ec || base.empty())
                return JS_ThrowTypeError(ctx, "File.list(path) requires a path");
            target = base;
        }
        else
        {
            const JS::File_rule *rule = current_file_rule(*policy);
            if (rule == nullptr || rule->read_dirs.empty())
                return JS_ThrowTypeError(ctx, "file reading is disabled for this script");
            target = std::filesystem::u8path(rule->read_dirs.front());
        }
    }

    // 读锁:遍历期间该目录不会被同进程的其它线程改动
    const auto lock = file_read_lock(target);

    std::error_code ec;
    if (!std::filesystem::is_directory(target, ec))
        return JS_ThrowTypeError(ctx, "not a directory");

    JSValue array = JS_NewArray(ctx);
    if (JS_IsException(array))
        return array;

    uint32_t index = 0;
    for (std::filesystem::directory_iterator it(target, ec), end; !ec && it != end;
            it.increment(ec))
    {
        std::string name = it->path().filename().u8string();
        std::error_code sub;
        if (it->is_directory(sub))
            name.push_back('/');

        JSValue item = JS_NewStringLen(ctx, name.c_str(), name.size());
        if (JS_IsException(item) || JS_SetPropertyUint32(ctx, array, index, item) < 0)
        {
            JS_FreeValue(ctx, array);
            return JS_EXCEPTION;
        }
        ++index;
    }
    return array;
}

JSValue file_js_remove(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "File.remove(path) requires a path");

    const auto policy = file_policy_snapshot();

    std::filesystem::path target;
    if (!file_arg_path(ctx, *policy, argv[0], File_access::Write, target))
        return JS_EXCEPTION;

    // 写锁:与同一路径上的读写互斥
    const auto lock = file_write_lock(target);

    std::error_code ec;
    const bool removed = std::filesystem::remove(target, ec);
    return JS_NewBool(ctx, removed && !ec);
}

JSValue file_js_mkdir(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "File.mkdir(path) requires a path");

    const auto policy = file_policy_snapshot();

    std::filesystem::path target;
    if (!file_arg_path(ctx, *policy, argv[0], File_access::Write, target))
        return JS_EXCEPTION;

    // 写锁:两个线程同时 mkdir 同一目录时不会互相干扰
    const auto lock = file_write_lock(target);

    std::error_code ec;
    std::filesystem::create_directories(target, ec);
    return JS_NewBool(ctx, !ec);
}

JSValue dirs_to_array(JSContext *ctx, const std::vector<std::string> &dirs)
{
    JSValue array = JS_NewArray(ctx);
    if (JS_IsException(array))
        return array;

    for (std::size_t i = 0; i < dirs.size(); ++i)
    {
        JSValue item = JS_NewStringLen(ctx, dirs[i].c_str(), dirs[i].size());
        if (JS_IsException(item) ||
                JS_SetPropertyUint32(ctx, array, static_cast<uint32_t>(i), item) < 0)
        {
            JS_FreeValue(ctx, array);
            return JS_EXCEPTION;
        }
    }
    return array;
}

/*
 *@brief File.root():第一条读目录(没有则空串,保留旧语义)
 */
JSValue file_js_root(JSContext *ctx, JSValueConst, int, JSValueConst *)
{
    const auto policy = file_policy_snapshot();
    if (script_has_full_access(*policy))
    {
        // 完全访问:根目录就是脚本目录(未配置脚本目录时返回空串)
        return JS_NewStringLen(ctx, policy->script_dir.c_str(), policy->script_dir.size());
    }

    const JS::File_rule *rule = current_file_rule(*policy);
    if (rule == nullptr || rule->read_dirs.empty())
        return JS_NewString(ctx, "");

    const std::string &root = rule->read_dirs.front();
    return JS_NewStringLen(ctx, root.c_str(), root.size());
}

/*
 *@brief File.roots():当前脚本的读 / 写目录列表 {read: [], write: []}
 */
JSValue file_js_roots(JSContext *ctx, JSValueConst, int, JSValueConst *)
{
    const auto policy = file_policy_snapshot();
    if (script_has_full_access(*policy))
    {
        // 完全访问:读写范围都是整个文件系统,用 "*" 表示
        static const std::vector<std::string> all = {"*"};

        JSValue object = JS_NewObject(ctx);
        if (JS_IsException(object))
            return object;

        JSValue read_array = dirs_to_array(ctx, all);
        if (JS_IsException(read_array))
        {
            JS_FreeValue(ctx, object);
            return JS_EXCEPTION;
        }
        JS_SetPropertyStr(ctx, object, "read", read_array);

        JSValue write_array = dirs_to_array(ctx, all);
        if (JS_IsException(write_array))
        {
            JS_FreeValue(ctx, object);
            return JS_EXCEPTION;
        }
        JS_SetPropertyStr(ctx, object, "write", write_array);
        return object;
    }

    const JS::File_rule *rule = current_file_rule(*policy);
    static const std::vector<std::string> none;
    const std::vector<std::string> &read_dirs = (rule != nullptr) ? rule->read_dirs : none;
    const std::vector<std::string> &write_dirs = (rule != nullptr) ? rule->write_dirs : none;

    JSValue object = JS_NewObject(ctx);
    if (JS_IsException(object))
        return object;

    JSValue read_array = dirs_to_array(ctx, read_dirs);
    if (JS_IsException(read_array))
    {
        JS_FreeValue(ctx, object);
        return JS_EXCEPTION;
    }
    JS_SetPropertyStr(ctx, object, "read", read_array);

    JSValue write_array = dirs_to_array(ctx, write_dirs);
    if (JS_IsException(write_array))
    {
        JS_FreeValue(ctx, object);
        return JS_EXCEPTION;
    }
    JS_SetPropertyStr(ctx, object, "write", write_array);
    return object;
}

JSValue file_js_can_read(JSContext *ctx, JSValueConst, int, JSValueConst *)
{
    const auto policy = file_policy_snapshot();
    if (script_has_full_access(*policy))
        return JS_NewBool(ctx, true);
    const JS::File_rule *rule = current_file_rule(*policy);
    return JS_NewBool(ctx, rule != nullptr && !rule->read_dirs.empty());
}

JSValue file_js_can_write(JSContext *ctx, JSValueConst, int, JSValueConst *)
{
    const auto policy = file_policy_snapshot();
    if (script_has_full_access(*policy))
        return JS_NewBool(ctx, true);
    const JS::File_rule *rule = current_file_rule(*policy);
    return JS_NewBool(ctx, rule != nullptr && !rule->write_dirs.empty());
}

const JSCFunctionListEntry file_funcs[] = {
    JS_CFUNC_DEF("read", 1, file_js_read),
    JS_CFUNC_DEF("readText", 1, file_js_read_text),
    JS_CFUNC_DEF("getline", 1, file_js_getline),
    JS_CFUNC_DEF("write", 2, file_js_write),
    JS_CFUNC_DEF("append", 2, file_js_append),
    JS_CFUNC_DEF("exists", 1, file_js_exists),
    JS_CFUNC_DEF("size", 1, file_js_size),
    JS_CFUNC_DEF("list", 1, file_js_list),
    JS_CFUNC_DEF("remove", 1, file_js_remove),
    JS_CFUNC_DEF("mkdir", 1, file_js_mkdir),
    JS_CFUNC_DEF("root", 0, file_js_root),
    JS_CFUNC_DEF("roots", 0, file_js_roots),
    JS_CFUNC_DEF("canRead", 0, file_js_can_read),
    JS_CFUNC_DEF("canWrite", 0, file_js_can_write),
};

/*
 *@brief 安装全局对象 File(策略由 C++ 侧配置,脚本无法修改)
 */
void install_file(JSContext *ctx)
{
    JSValue file = JS_NewObject(ctx);
    if (JS_IsException(file))
    {
        Log::error("JS: cannot create File object");
        return;
    }
    JS_SetPropertyFunctionList(ctx, file, file_funcs,
                               sizeof(file_funcs) / sizeof(file_funcs[0]));

    JSValue global = JS_GetGlobalObject(ctx);
    if (JS_IsException(global))
    {
        Log::error("JS: cannot get global object for File");
        JS_FreeValue(ctx, file);
        return;
    }
    JS_SetPropertyStr(ctx, global, "File", file);
    JS_FreeValue(ctx, global);
}

// ==================== SQLite 接口(全局对象 Sqlite) ====================

/*
 *@struct Js_sqlite_db
 *@brief 一个 JS 侧数据库句柄(每个对象独占一条 sqlite3 连接)
 *
 *@note  连接由 JS 对象持有:对象被回收时 finalizer 关闭它;
 *       脚本结束时整个 JSRuntime 释放,连接随之关闭,不会跨请求泄漏。
 */
struct Js_sqlite_db
{
    sqlite3 *db = nullptr; ///< 连接(由 sqlite3_open_v2 打开)
    std::string path;      ///< 打开时的绝对路径(报错用)
};

JSClassID g_sqlite_db_class = 0; ///< JS 侧数据库对象的 class id

/*
 *@brief 数据库对象 finalizer:关闭连接并释放句柄
 */
void sqlite_db_finalizer(JSRuntime *, JSValue val)
{
    auto *handle = static_cast<Js_sqlite_db *>(JS_GetOpaque(val, g_sqlite_db_class));
    if (handle == nullptr)
        return;
    if (handle->db != nullptr)
        sqlite3_close_v2(handle->db);
    delete handle;
}

/*
 *@brief 取出 this 上的数据库句柄;连接已关闭时抛出 TypeError
 */
Js_sqlite_db *sqlite_self(JSContext *ctx, JSValueConst this_val)
{
    auto *handle = static_cast<Js_sqlite_db *>(JS_GetOpaque(this_val, g_sqlite_db_class));
    if (handle == nullptr || handle->db == nullptr)
    {
        JS_ThrowTypeError(ctx, "database is closed");
        return nullptr;
    }
    return handle;
}

/*
 *@brief 取 thiz 上的句柄(不要求连接已打开,用于 close / path)
 */
Js_sqlite_db *sqlite_handle(JSContext *ctx, JSValueConst this_val)
{
    auto *handle = static_cast<Js_sqlite_db *>(JS_GetOpaque(this_val, g_sqlite_db_class));
    if (handle == nullptr)
        JS_ThrowTypeError(ctx, "not a Sqlite database");
    return handle;
}

/*
 *@brief JS 值 -> SQLite 参数(undefined / null -> NULL)
 *@note  整数值按 INTEGER 绑定,其它数字按 REAL;字符串按 TEXT,
 *       Uint8Array / ArrayBuffer 按 BLOB;失败时在上下文中抛出异常
 */
bool sqlite_bind_value(JSContext *ctx, sqlite3_stmt *stmt, int index, JSValueConst val)
{
    if (JS_IsUndefined(val) || JS_IsNull(val))
    {
        sqlite3_bind_null(stmt, index);
        return true;
    }
    if (JS_IsBool(val))
    {
        sqlite3_bind_int(stmt, index, JS_ToBool(ctx, val) > 0 ? 1 : 0);
        return true;
    }
    if (JS_IsNumber(val))
    {
        double number = 0;
        if (JS_ToFloat64(ctx, &number, val) != 0)
            return false;

        // 2^53 以内的整数值用 INTEGER,避免 ID / 时间戳变成 REAL
        if (number == std::floor(number) && std::fabs(number) <= 9007199254740992.0)
        {
            int64_t integer = 0;
            if (JS_ToInt64(ctx, &integer, val) == 0)
            {
                sqlite3_bind_int64(stmt, index, static_cast<sqlite3_int64>(integer));
                return true;
            }
            JS_FreeValue(ctx, JS_GetException(ctx));
        }
        sqlite3_bind_double(stmt, index, number);
        return true;
    }

    std::string bytes;
    if (!js_value_to_bytes(ctx, val, bytes))
        return false;

    const char *data = bytes.empty() ? "" : bytes.data();
    const int size = static_cast<int>(bytes.size());
    if (JS_IsString(val))
        sqlite3_bind_text(stmt, index, data, size, SQLITE_TRANSIENT);
    else
        sqlite3_bind_blob(stmt, index, data, size, SQLITE_TRANSIENT);
    return true;
}

/*
 *@brief 列值 -> JS 值(INTEGER / REAL / TEXT / BLOB / NULL)
 */
JSValue sqlite_column_value(JSContext *ctx, sqlite3_stmt *stmt, int column)
{
    switch (sqlite3_column_type(stmt, column))
    {
    case SQLITE_INTEGER:
        return JS_NewInt64(ctx, static_cast<int64_t>(sqlite3_column_int64(stmt, column)));
    case SQLITE_FLOAT:
        return JS_NewFloat64(ctx, sqlite3_column_double(stmt, column));
    case SQLITE_TEXT:
    {
        const unsigned char *text = sqlite3_column_text(stmt, column);
        const int size = sqlite3_column_bytes(stmt, column);
        return JS_NewStringLen(
                   ctx, text == nullptr ? "" : reinterpret_cast<const char *>(text),
                   static_cast<size_t>(size));
    }
    case SQLITE_BLOB:
    {
        const void *data = sqlite3_column_blob(stmt, column);
        const int size = sqlite3_column_bytes(stmt, column);
        if (data == nullptr || size <= 0)
            return js_new_bytes(ctx, std::string());
        return js_new_bytes(ctx, std::string(static_cast<const char *>(data),
                                             static_cast<size_t>(size)));
    }
    default:
        return JS_NULL;
    }
}

/*
 *@brief 预备语句并绑定参数(参数从 1 开始,多余实参忽略,缺少的按 NULL)
 */
sqlite3_stmt *sqlite_prepare(JSContext *ctx, Js_sqlite_db *handle, const std::string &sql,
                             int argc, JSValueConst *argv)
{
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(handle->db, sql.c_str(), static_cast<int>(sql.size()), &stmt,
                           nullptr) != SQLITE_OK)
    {
        JS_ThrowTypeError(ctx, "sqlite: %s", sqlite3_errmsg(handle->db));
        return nullptr;
    }

    const int count = sqlite3_bind_parameter_count(stmt);
    for (int i = 1; i <= count && i <= argc; ++i)
    {
        if (!sqlite_bind_value(ctx, stmt, i, argv[i - 1]))
        {
            sqlite3_finalize(stmt);
            return nullptr;
        }
    }
    return stmt;
}

/*
 *@brief db.exec(sql):执行一段(可多条) SQL
 */
JSValue sqlite_exec(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv)
{
    Js_sqlite_db *handle = sqlite_self(ctx, this_val);
    if (handle == nullptr)
        return JS_EXCEPTION;
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "db.exec(sql) requires a SQL string");

    std::string sql;
    if (!js_value_to_string(ctx, argv[0], sql))
        return JS_EXCEPTION;

    char *error = nullptr;
    if (sqlite3_exec(handle->db, sql.c_str(), nullptr, nullptr, &error) != SQLITE_OK)
    {
        const std::string message = (error != nullptr) ? error : sqlite3_errmsg(handle->db);
        sqlite3_free(error);
        return JS_ThrowTypeError(ctx, "sqlite: %s", message.c_str());
    }
    return JS_NewBool(ctx, true);
}

/*
 *@brief db.run(sql, ...params):执行写语句,返回 {changes, lastInsertRowid}
 */
JSValue sqlite_run(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv)
{
    Js_sqlite_db *handle = sqlite_self(ctx, this_val);
    if (handle == nullptr)
        return JS_EXCEPTION;
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "db.run(sql, ...params) requires a SQL string");

    std::string sql;
    if (!js_value_to_string(ctx, argv[0], sql))
        return JS_EXCEPTION;

    sqlite3_stmt *stmt = sqlite_prepare(ctx, handle, sql, argc - 1, argv + 1);
    if (stmt == nullptr)
        return JS_EXCEPTION;

    JSValue result = JS_EXCEPTION;
    const int rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE || rc == SQLITE_ROW)
    {
        result = JS_NewObject(ctx);
        if (!JS_IsException(result))
        {
            JS_SetPropertyStr(ctx, result, "changes",
                              JS_NewInt64(ctx, static_cast<int64_t>(
                                              sqlite3_changes(handle->db))));
            JS_SetPropertyStr(ctx, result, "lastInsertRowid",
                              JS_NewInt64(ctx, static_cast<int64_t>(
                                              sqlite3_last_insert_rowid(handle->db))));
        }
    }
    else
    {
        JS_ThrowTypeError(ctx, "sqlite: %s", sqlite3_errmsg(handle->db));
    }
    sqlite3_finalize(stmt);
    return result;
}

/*
 *@brief db.query(sql, ...params):查询,返回行数组(数组上的 columns 是列名)
 */
JSValue sqlite_query(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv)
{
    Js_sqlite_db *handle = sqlite_self(ctx, this_val);
    if (handle == nullptr)
        return JS_EXCEPTION;
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "db.query(sql, ...params) requires a SQL string");

    std::string sql;
    if (!js_value_to_string(ctx, argv[0], sql))
        return JS_EXCEPTION;

    sqlite3_stmt *stmt = sqlite_prepare(ctx, handle, sql, argc - 1, argv + 1);
    if (stmt == nullptr)
        return JS_EXCEPTION;

    const int count = sqlite3_column_count(stmt);
    std::vector<std::string> columns;
    columns.reserve(static_cast<std::size_t>(count));
    for (int i = 0; i < count; ++i)
    {
        const char *name = sqlite3_column_name(stmt, i);
        columns.emplace_back(name == nullptr ? "" : name);
    }

    JSValue rows = JS_NewArray(ctx);
    if (JS_IsException(rows))
    {
        sqlite3_finalize(stmt);
        return rows;
    }

    uint32_t index = 0;
    for (;;)
    {
        const int rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE)
            break;
        if (rc != SQLITE_ROW)
        {
            sqlite3_finalize(stmt);
            JS_FreeValue(ctx, rows);
            return JS_ThrowTypeError(ctx, "sqlite: %s", sqlite3_errmsg(handle->db));
        }

        JSValue row = JS_NewObject(ctx);
        if (JS_IsException(row))
        {
            sqlite3_finalize(stmt);
            JS_FreeValue(ctx, rows);
            return JS_EXCEPTION;
        }

        bool ok = true;
        for (int i = 0; i < count; ++i)
        {
            JSValue value = sqlite_column_value(ctx, stmt, i);
            // JS_SetPropertyStr 会接管 value 的引用(成功与失败都是)
            if (JS_IsException(value) ||
                    JS_SetPropertyStr(ctx, row, columns[static_cast<std::size_t>(i)].c_str(),
                                      value) < 0)
            {
                ok = false;
                break;
            }
        }
        if (!ok)
        {
            JS_FreeValue(ctx, row);
            sqlite3_finalize(stmt);
            JS_FreeValue(ctx, rows);
            return JS_EXCEPTION;
        }
        if (JS_SetPropertyUint32(ctx, rows, index, row) < 0)
        {
            sqlite3_finalize(stmt);
            JS_FreeValue(ctx, rows);
            return JS_EXCEPTION;
        }
        ++index;
    }

    sqlite3_finalize(stmt);

    // 列名放在数组属性上,方便知道结果里有哪些字段
    JSValue column_array = dirs_to_array(ctx, columns);
    if (!JS_IsException(column_array))
        JS_SetPropertyStr(ctx, rows, "columns", column_array);
    return rows;
}

/*
 *@brief db.close():关闭连接(幂等)
 */
JSValue sqlite_close(JSContext *ctx, JSValueConst this_val, int, JSValueConst *)
{
    Js_sqlite_db *handle = sqlite_handle(ctx, this_val);
    if (handle == nullptr)
        return JS_EXCEPTION;
    if (handle->db != nullptr)
    {
        sqlite3 *db = handle->db;
        if (sqlite3_close_v2(db) != SQLITE_OK)
            return JS_ThrowTypeError(ctx, "sqlite: %s", sqlite3_errmsg(db));
        handle->db = nullptr;
    }
    return JS_NewBool(ctx, true);
}

JSValue sqlite_path(JSContext *ctx, JSValueConst this_val, int, JSValueConst *)
{
    Js_sqlite_db *handle = sqlite_handle(ctx, this_val);
    if (handle == nullptr)
        return JS_EXCEPTION;
    return JS_NewStringLen(ctx, handle->path.c_str(), handle->path.size());
}

JSValue sqlite_changes(JSContext *ctx, JSValueConst this_val, int, JSValueConst *)
{
    Js_sqlite_db *handle = sqlite_self(ctx, this_val);
    if (handle == nullptr)
        return JS_EXCEPTION;
    return JS_NewInt64(ctx, static_cast<int64_t>(sqlite3_changes(handle->db)));
}

JSValue sqlite_last_insert_rowid(JSContext *ctx, JSValueConst this_val, int, JSValueConst *)
{
    Js_sqlite_db *handle = sqlite_self(ctx, this_val);
    if (handle == nullptr)
        return JS_EXCEPTION;
    return JS_NewInt64(ctx,
                       static_cast<int64_t>(sqlite3_last_insert_rowid(handle->db)));
}

JSValue sqlite_busy_timeout(JSContext *ctx, JSValueConst this_val, int argc,
                            JSValueConst *argv)
{
    Js_sqlite_db *handle = sqlite_self(ctx, this_val);
    if (handle == nullptr)
        return JS_EXCEPTION;
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "db.busyTimeout(ms) requires milliseconds");

    int32_t ms = 0;
    if (JS_ToInt32(ctx, &ms, argv[0]) < 0)
        return JS_EXCEPTION;
    sqlite3_busy_timeout(handle->db, ms < 0 ? 0 : ms);
    return JS_NewBool(ctx, true);
}

const JSCFunctionListEntry sqlite_db_funcs[] = {
    JS_CFUNC_DEF("exec", 1, sqlite_exec),
    JS_CFUNC_DEF("query", 1, sqlite_query),
    JS_CFUNC_DEF("run", 1, sqlite_run),
    JS_CFUNC_DEF("close", 0, sqlite_close),
    JS_CFUNC_DEF("path", 0, sqlite_path),
    JS_CFUNC_DEF("changes", 0, sqlite_changes),
    JS_CFUNC_DEF("lastInsertRowid", 0, sqlite_last_insert_rowid),
    JS_CFUNC_DEF("busyTimeout", 1, sqlite_busy_timeout),
};

/*
 *@brief Sqlite.open(path[, {readonly: true}]):打开数据库
 */
JSValue sqlite_js_open(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "Sqlite.open(path[, options]) requires a path");

    std::string raw;
    if (!js_value_to_string(ctx, argv[0], raw))
        return JS_EXCEPTION;

    bool readonly = false;
    if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1]))
    {
        if (!JS_IsObject(argv[1]))
            return JS_ThrowTypeError(ctx, "Sqlite.open: options must be an object");

        JSValue flag = JS_GetPropertyStr(ctx, argv[1], "readonly");
        if (JS_IsException(flag))
            return JS_EXCEPTION;
        readonly = JS_ToBool(ctx, flag) > 0;
        JS_FreeValue(ctx, flag);
    }

    const auto policy = file_policy_snapshot();
    std::filesystem::path target;
    bool full_access = false;
    if (!resolve_sql_path(ctx, *policy, raw, readonly, target, full_access))
        return JS_EXCEPTION;

    const std::string path = target.u8string();
    const int flags = readonly ? SQLITE_OPEN_READONLY
                      : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);

    sqlite3 *db = nullptr;
    if (sqlite3_open_v2(path.c_str(), &db, flags, nullptr) != SQLITE_OK)
    {
        const std::string message =
            (db != nullptr) ? sqlite3_errmsg(db) : "cannot open database";
        if (db != nullptr)
            sqlite3_close_v2(db);
        Log::warning("JS: sqlite open failed: " + path + " (" + message + ")");
        return JS_ThrowTypeError(ctx, "sqlite: %s", message.c_str());
    }

    // 并发写时最多等 5 秒再报 SQLITE_BUSY,避免其它线程写库时脚本直接失败
    sqlite3_busy_timeout(db, 5000);

    auto *handle = new (std::nothrow) Js_sqlite_db();
    if (handle == nullptr)
    {
        sqlite3_close_v2(db);
        return JS_ThrowInternalError(ctx, "sqlite: out of memory");
    }
    handle->db = db;
    handle->path = path;

    JSValue object = JS_NewObjectClass(ctx, g_sqlite_db_class);
    if (JS_IsException(object))
    {
        sqlite3_close_v2(db);
        delete handle;
        return object;
    }
    JS_SetOpaque(object, handle);
    JS_SetPropertyFunctionList(ctx, object, sqlite_db_funcs,
                               sizeof(sqlite_db_funcs) / sizeof(sqlite_db_funcs[0]));
    return object;
}

/*
 *@brief 当前脚本是否拥有任何 SQL 权限(没有就不安装全局对象)
 */
bool script_has_sql_access(const JS::File_policy &policy)
{
    if (script_has_full_access(policy))
        return true;
    if (policy.sql_rules.empty())
        return false;

    const JS::Sql_rule *rule =
        match_sql_rule(policy, current_script_key(policy), current_script_abs());
    return rule != nullptr && (!rule->read_dbs.empty() || !rule->write_dbs.empty());
}

/*
 *@brief 安装全局对象 Sqlite
 *@note  默认完全关闭:没有 SQL 权限的脚本里连 Sqlite 这个名字都不存在;
 *       即便装上,open 时仍会再校一次权限
 */
void install_sqlite(JSContext *ctx, JSRuntime *rt)
{
    const auto policy = file_policy_snapshot();
    if (!script_has_sql_access(*policy))
        return;

    register_class(rt, g_sqlite_db_class, "SqliteDB", sqlite_db_finalizer);

    JSValue sqlite = JS_NewObject(ctx);
    if (JS_IsException(sqlite))
    {
        Log::error("JS: cannot create Sqlite object");
        return;
    }

    JSValue open = JS_NewCFunction(ctx, sqlite_js_open, "open", 2);
    if (JS_IsException(open) || JS_SetPropertyStr(ctx, sqlite, "open", open) < 0)
    {
        Log::error("JS: cannot install Sqlite.open");
        JS_FreeValue(ctx, sqlite);
        return;
    }

    JSValue global = JS_GetGlobalObject(ctx);
    if (JS_IsException(global))
    {
        Log::error("JS: cannot get global object for Sqlite");
        JS_FreeValue(ctx, sqlite);
        return;
    }
    JS_SetPropertyStr(ctx, global, "Sqlite", sqlite);
    JS_FreeValue(ctx, global);
}

// ==================== 日志接口(console.* / 全局函数) ====================

void sink_log(const std::string &msg) {
    Log::log(msg);
}
void sink_debug(const std::string &msg) {
    Log::debug(msg);
}
void sink_warning(const std::string &msg) {
    Log::warning(msg);
}
void sink_error(const std::string &msg) {
    Log::error(msg);
}
void sink_access(const std::string &msg) {
    Log::access(msg);
}

/*
 *@brief 把脚本的一次日志调用转发到框架日志
 */
template <void (*Sink)(const std::string &)>
JSValue js_log_bridge(JSContext *ctx, [[maybe_unused]] JSValueConst this_val,
                      int argc, JSValueConst *argv)
{
    std::string msg;
    if (!js_args_to_string(ctx, argc, argv, msg))
        return JS_EXCEPTION;

    try
    {
        Sink(msg);
    }
    catch (...)
    {
        // 写日志失败不能影响脚本执行
    }
    return JS_UNDEFINED;
}

/*
 *@brief 安装 console.{log,debug,warn,error,access} 以及同名全局函数
 */
void install_log(JSContext *ctx)
{
    JSValue global = JS_GetGlobalObject(ctx);
    if (JS_IsException(global))
    {
        Log::error("JS: cannot get global object, log bridge disabled");
        return;
    }

    JSValue console = JS_NewObject(ctx);
    if (JS_IsException(console))
    {
        Log::error("JS: cannot create console object");
        JS_FreeValue(ctx, global);
        return;
    }

    struct BridgeEntry
    {
        const char *name;
        JSCFunction *func;
    };

    const BridgeEntry entries[] = {
        {"log", js_log_bridge<sink_log>},
        {"debug", js_log_bridge<sink_debug>},
        {"warn", js_log_bridge<sink_warning>},
        {"error", js_log_bridge<sink_error>},
        {"access", js_log_bridge<sink_access>},
    };

    bool ok = true;
    for (const BridgeEntry &entry : entries)
    {
        JSValue func = JS_NewCFunction(ctx, entry.func, entry.name, 1);
        if (JS_IsException(func))
        {
            ok = false;
            break;
        }

        // console.<name> 与全局 <name> 指向同一个函数对象
        if (JS_SetPropertyStr(ctx, console, entry.name, JS_DupValue(ctx, func)) < 0)
        {
            JS_FreeValue(ctx, func);
            ok = false;
            break;
        }
        if (JS_SetPropertyStr(ctx, global, entry.name, func) < 0)
        {
            ok = false;
            break;
        }
    }

    if (!ok)
    {
        Log::error("JS: failed to install log bridge");
        JS_FreeValue(ctx, console);
    }
    else
    {
        // 成功后引用交给 global,不再释放
        JS_SetPropertyStr(ctx, global, "console", console);
    }

    JS_FreeValue(ctx, global);
}

// ==================== Cookie 类 ====================

JSClassID g_cookie_class_id = 0; ///< JS 侧 `Cookie` 的 class id

void cookie_finalizer(JSRuntime *rt, JSValue val)
{
    (void)rt;
    delete static_cast<HTTP::Cookie *>(JS_GetOpaque(val, g_cookie_class_id));
}

/*
 *@brief 取出 this 上的 Cookie;类型不对时抛出 TypeError
 */
HTTP::Cookie *cookie_self(JSContext *ctx, JSValueConst this_val)
{
    HTTP::Cookie *cookie =
        static_cast<HTTP::Cookie *>(JS_GetOpaque(this_val, g_cookie_class_id));
    if (!cookie)
        JS_ThrowTypeError(ctx, "not a Cookie instance");
    return cookie;
}

enum CookieStrField
{
    CookieFieldName,
    CookieFieldValue,
    CookieFieldPath,
    CookieFieldDomain,
    CookieFieldExpires,
    CookieFieldSameSite
};

std::string *cookie_field(HTTP::Cookie *cookie, int field)
{
    switch (field)
    {
    case CookieFieldName:
        return &cookie->name;
    case CookieFieldValue:
        return &cookie->value;
    case CookieFieldPath:
        return &cookie->path;
    case CookieFieldDomain:
        return &cookie->domain;
    case CookieFieldExpires:
        return &cookie->expires;
    case CookieFieldSameSite:
    default:
        return &cookie->same_site;
    }
}

JSValue cookie_get_string(JSContext *ctx, JSValueConst this_val, int field)
{
    HTTP::Cookie *cookie = cookie_self(ctx, this_val);
    if (!cookie)
        return JS_EXCEPTION;
    const std::string *value = cookie_field(cookie, field);
    return JS_NewStringLen(ctx, value->c_str(), value->size());
}

JSValue cookie_set_string(JSContext *ctx, JSValueConst this_val, JSValueConst val, int field)
{
    HTTP::Cookie *cookie = cookie_self(ctx, this_val);
    if (!cookie)
        return JS_EXCEPTION;

    std::string text;
    if (!js_value_to_string(ctx, val, text))
        return JS_EXCEPTION;
    *cookie_field(cookie, field) = std::move(text);
    return JS_DupValue(ctx, val);
}

JSValue cookie_get_max_age(JSContext *ctx, JSValueConst this_val)
{
    HTTP::Cookie *cookie = cookie_self(ctx, this_val);
    if (!cookie)
        return JS_EXCEPTION;
    return JS_NewInt32(ctx, static_cast<int32_t>(cookie->max_age));
}

JSValue cookie_set_max_age(JSContext *ctx, JSValueConst this_val, JSValueConst val)
{
    HTTP::Cookie *cookie = cookie_self(ctx, this_val);
    if (!cookie)
        return JS_EXCEPTION;

    int32_t seconds = 0;
    if (JS_ToInt32(ctx, &seconds, val) < 0)
        return JS_EXCEPTION;
    cookie->max_age = seconds;
    return JS_DupValue(ctx, val);
}

JSValue cookie_get_flag(JSContext *ctx, JSValueConst this_val, int flag)
{
    HTTP::Cookie *cookie = cookie_self(ctx, this_val);
    if (!cookie)
        return JS_EXCEPTION;
    return JS_NewBool(ctx, flag == 0 ? cookie->secure : cookie->http_only);
}

JSValue cookie_set_flag(JSContext *ctx, JSValueConst this_val, JSValueConst val, int flag)
{
    HTTP::Cookie *cookie = cookie_self(ctx, this_val);
    if (!cookie)
        return JS_EXCEPTION;

    const int on = JS_ToBool(ctx, val);
    if (on < 0)
        return JS_EXCEPTION;
    if (flag == 0)
        cookie->secure = (on != 0);
    else
        cookie->http_only = (on != 0);
    return JS_DupValue(ctx, val);
}

JSValue cookie_to_string(JSContext *ctx, JSValueConst this_val,
                         [[maybe_unused]] int argc, [[maybe_unused]] JSValueConst *argv)
{
    HTTP::Cookie *cookie = cookie_self(ctx, this_val);
    if (!cookie)
        return JS_EXCEPTION;
    const std::string text = cookie->to_string();
    return JS_NewStringLen(ctx, text.c_str(), text.size());
}

const JSCFunctionListEntry cookie_proto_funcs[] = {
    JS_CGETSET_MAGIC_DEF("name", cookie_get_string, cookie_set_string, CookieFieldName),
    JS_CGETSET_MAGIC_DEF("value", cookie_get_string, cookie_set_string, CookieFieldValue),
    JS_CGETSET_MAGIC_DEF("path", cookie_get_string, cookie_set_string, CookieFieldPath),
    JS_CGETSET_MAGIC_DEF("domain", cookie_get_string, cookie_set_string, CookieFieldDomain),
    JS_CGETSET_MAGIC_DEF("expires", cookie_get_string, cookie_set_string, CookieFieldExpires),
    JS_CGETSET_MAGIC_DEF("sameSite", cookie_get_string, cookie_set_string,
    CookieFieldSameSite),
    JS_CGETSET_DEF("maxAge", cookie_get_max_age, cookie_set_max_age),
    JS_CGETSET_MAGIC_DEF("secure", cookie_get_flag, cookie_set_flag, 0),
    JS_CGETSET_MAGIC_DEF("httpOnly", cookie_get_flag, cookie_set_flag, 1),
    JS_CFUNC_DEF("toString", 0, cookie_to_string),
};

/*
 *@brief new Cookie(name, value)
 */
JSValue js_cookie_ctor(JSContext *ctx, [[maybe_unused]] JSValueConst new_target,
                       int argc, JSValueConst *argv)
{
    JSValue obj = JS_NewObjectClass(ctx, g_cookie_class_id);
    if (JS_IsException(obj))
        return obj;

    auto *cookie = new (std::nothrow) HTTP::Cookie();
    if (!cookie)
    {
        JS_FreeValue(ctx, obj);
        return JS_ThrowInternalError(ctx, "out of memory");
    }

    if ((argc >= 1 && !js_value_to_string(ctx, argv[0], cookie->name)) ||
            (argc >= 2 && !js_value_to_string(ctx, argv[1], cookie->value)))
    {
        delete cookie;
        JS_FreeValue(ctx, obj);
        return JS_EXCEPTION;
    }

    JS_SetOpaque(obj, cookie);
    return obj;
}

/*
 *@brief 安装全局构造函数 Cookie 及其原型
 */
void install_cookie(JSContext *ctx)
{
    register_class(JS_GetRuntime(ctx), g_cookie_class_id, "Cookie", cookie_finalizer);

    // 原型对象:引用随后交给 class(不在这里释放)
    JSValue proto = JS_NewObject(ctx);
    if (JS_IsException(proto))
    {
        Log::error("JS: cannot create Cookie prototype");
        return;
    }
    JS_SetPropertyFunctionList(ctx, proto, cookie_proto_funcs,
                               sizeof(cookie_proto_funcs) / sizeof(cookie_proto_funcs[0]));
    JS_SetClassProto(ctx, g_cookie_class_id, proto);

    JSValue global = JS_GetGlobalObject(ctx);
    if (JS_IsException(global))
    {
        Log::error("JS: cannot get global object for Cookie");
        return;
    }

    JSValue ctor = JS_NewCFunction2(ctx, js_cookie_ctor, "Cookie", 2,
                                    JS_CFUNC_constructor, 0);
    if (JS_IsException(ctor))
    {
        Log::error("JS: cannot create Cookie constructor");
        JS_FreeValue(ctx, global);
        return;
    }

    JS_SetPropertyStr(ctx, global, "Cookie", ctor);
    JS_FreeValue(ctx, global);
}

/*
 *@brief 把脚本传入的对象(普通对象或 Cookie 实例)转成 HTTP::Cookie
 */
bool cookie_from_js(JSContext *ctx, JSValueConst val, HTTP::Cookie &out)
{
    if (JS_IsString(val))
        return js_value_to_string(ctx, val, out.value);

    auto *native = static_cast<HTTP::Cookie *>(JS_GetOpaque(val, g_cookie_class_id));
    if (native)
    {
        out = *native;
        return true;
    }

    if (!JS_IsObject(val))
    {
        JS_ThrowTypeError(ctx, "cookie(...) expects a Cookie instance or an object");
        return false;
    }

    return js_object_get_string(ctx, val, "name", out.name) &&
           js_object_get_string(ctx, val, "value", out.value) &&
           js_object_get_string(ctx, val, "path", out.path) &&
           js_object_get_string(ctx, val, "domain", out.domain) &&
           js_object_get_string(ctx, val, "expires", out.expires) &&
           js_object_get_string(ctx, val, "sameSite", out.same_site) &&
           js_object_get_int(ctx, val, "maxAge", out.max_age) &&
           js_object_get_bool(ctx, val, "secure", out.secure) &&
           js_object_get_bool(ctx, val, "httpOnly", out.http_only);
}

// ==================== 请求对象(HTTP.get) ====================

/*
 *@struct install_http_get
 *@brief 把 HTTP::Header_get / TCP::Base_Link 映射成 `HTTP.get`
 *
 *@note  item_cache 是对当前 JS_HTTP 的引用,由 JS_HTTP::run() 保证在整个脚本
 *       执行期间存活;因此借用给 JS 的 this 指针在脚本运行期间始终有效。
 */
struct install_http_get
{
    inline static JSClassID class_id = 0; ///< 进程内共享的 class id

    JS_HTTP &item_cache;
    JSContext *ctx_ = nullptr;
    JSValue obj = JS_UNDEFINED;

    static void ensure_class(JSContext *ctx)
    {
        register_class(JS_GetRuntime(ctx), class_id, "HTTPGet", nullptr);
    }

    /*
     *@brief 统一的 JS 函数入口:取出 C++ this,再分发到成员函数
     */
    template <JSValue (install_http_get::*Func)(JSContext *, JSValueConst, int,
            JSValueConst *)>
    static JSValue trampoline(JSContext *ctx, JSValueConst this_val, int argc,
                              JSValueConst *argv)
    {
        auto *self = static_cast<install_http_get *>(JS_GetOpaque(this_val, class_id));
        if (!self)
            return JS_UNDEFINED; // this 已被销毁或不是本类实例
        return (self->*Func)(ctx, this_val, argc, argv);
    }

    /*
     *@brief 把成员函数挂到 `this` 对象上
     */
    template <JSValue (install_http_get::*Func)(JSContext *, JSValueConst, int,
            JSValueConst *)>
    void bind(const char *name)
    {
        JSValue func = JS_NewCFunction(ctx_, trampoline<Func>, name, 0);
        if (JS_IsException(func))
        {
            Log::error(std::string("JS: cannot create HTTP.get.") + name);
            return;
        }
        if (JS_SetPropertyStr(ctx_, obj, name, func) < 0)
            Log::error(std::string("JS: cannot define HTTP.get.") + name);
    }

    /*
     *@brief std::map -> 普通 JS 对象
     */
    static JSValue map_to_object(JSContext *ctx, const std::map<std::string, std::string> &src)
    {
        JSValue target = JS_NewObject(ctx);
        if (JS_IsException(target))
            return target;

        for (const auto &pair : src)
        {
            JSValue value = JS_NewStringLen(ctx, pair.second.c_str(), pair.second.size());
            if (JS_IsException(value) ||
                    JS_SetPropertyStr(ctx, target, pair.first.c_str(), value) < 0)
            {
                JS_FreeValue(ctx, target);
                return JS_EXCEPTION;
            }
        }
        return target;
    }

    // -------- 请求信息 --------

    JSValue method(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        const std::string &value = item_cache.Header.method;
        return JS_NewStringLen(ctx, value.c_str(), value.size());
    }

    JSValue url(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        const std::string &value = item_cache.Header.url;
        return JS_NewStringLen(ctx, value.c_str(), value.size());
    }

    JSValue rawUrl(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        const std::string &value = item_cache.Header.raw_url;
        return JS_NewStringLen(ctx, value.c_str(), value.size());
    }

    JSValue version(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        const std::string &value = item_cache.Header.version;
        return JS_NewStringLen(ctx, value.c_str(), value.size());
    }

    JSValue query(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        return map_to_object(ctx, item_cache.Header.query);
    }

    JSValue headers(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        return map_to_object(ctx, item_cache.Header.headers);
    }

    JSValue header(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        if (argc < 1)
            return JS_ThrowTypeError(ctx, "header(name) requires a name");

        std::string name;
        if (!js_value_to_string(ctx, argv[0], name))
            return JS_EXCEPTION;

        const std::string value = item_cache.Header.get(name);
        return JS_NewStringLen(ctx, value.c_str(), value.size());
    }

    JSValue cookies(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        return map_to_object(ctx, item_cache.Header.cookies);
    }

    JSValue cookie(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        if (argc < 1)
            return JS_ThrowTypeError(ctx, "cookie(name) requires a name");

        std::string name;
        if (!js_value_to_string(ctx, argv[0], name))
            return JS_EXCEPTION;

        const std::string value = item_cache.Header.cookie(name);
        return JS_NewStringLen(ctx, value.c_str(), value.size());
    }

    JSValue body(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        const std::string &value = item_cache.Header.body;
        return JS_NewStringLen(ctx, value.c_str(), value.size());
    }

    JSValue bodyBytes(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        // 请求体按原始字节交给脚本(Uint8Array),适合上传二进制数据
        return js_new_bytes(ctx, item_cache.Header.body);
    }

    JSValue peer(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        const std::string value = item_cache.Link.get_peer();
        return JS_NewStringLen(ctx, value.c_str(), value.size());
    }

    JSValue ip(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        const std::string value = item_cache.Link.get_ip();
        return JS_NewStringLen(ctx, value.c_str(), value.size());
    }

    // -------- 连接安全信息(HTTPS / WSS) --------

    /*
     *@brief 当前请求是否来自 HTTPS(启用 TLS 的连接)
     */
    JSValue isHttps(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        return JS_NewBool(ctx, item_cache.Link.is_tls());
    }

    /*
     *@brief 当前请求的 URL scheme:"https" 或 "http"
     */
    JSValue scheme(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        return JS_NewString(ctx, item_cache.Link.is_tls() ? "https" : "http");
    }

    /*
     *@brief 协商出的 TLS 协议版本(如 "TLS 1.3");非 TLS 连接返回空串
     */
    JSValue tlsProtocol(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        const std::string value = item_cache.Link.tls_protocol();
        return JS_NewStringLen(ctx, value.c_str(), value.size());
    }

    install_http_get(JSContext *ctx, JS_HTTP &item): item_cache(item), ctx_(ctx)
    {
        ensure_class(ctx);

        obj = JS_NewObjectClass(ctx, class_id);
        if (JS_IsException(obj))
        {
            obj = JS_UNDEFINED;
            Log::error("JS: cannot create HTTP.get object");
            return;
        }

        JS_SetOpaque(obj, this);

        bind<&install_http_get::method>("method");
        bind<&install_http_get::url>("url");
        bind<&install_http_get::rawUrl>("rawUrl");
        bind<&install_http_get::version>("version");
        bind<&install_http_get::query>("query");
        bind<&install_http_get::headers>("headers");
        bind<&install_http_get::header>("header");
        bind<&install_http_get::cookies>("cookies");
        bind<&install_http_get::cookie>("cookie");
        bind<&install_http_get::body>("body");
        bind<&install_http_get::bodyBytes>("bodyBytes");
        bind<&install_http_get::peer>("peer");
        bind<&install_http_get::ip>("ip");
        bind<&install_http_get::isHttps>("isHttps");
        bind<&install_http_get::scheme>("scheme");
        bind<&install_http_get::tlsProtocol>("tlsProtocol");

        // 挂到 HTTP 命名空间:HTTP.get
        JSValue global = JS_GetGlobalObject(ctx);
        if (JS_IsException(global))
        {
            Log::error("JS: cannot get global object for HTTP.get");
            return;
        }

        JSValue ns = js_ensure_object(ctx, global, "HTTP");
        if (!JS_IsException(ns))
        {
            if (JS_SetPropertyStr(ctx, ns, "get", JS_DupValue(ctx, obj)) < 0)
                Log::error("JS: cannot define HTTP.get");
            JS_FreeValue(ctx, ns);
        }
        else
        {
            Log::error("JS: cannot create HTTP namespace");
        }
        JS_FreeValue(ctx, global);
    }

    ~install_http_get()
    {
        JS_FreeValue(ctx_, obj);
    }

    // 只作为 JS 侧对象的宿主,禁止拷贝/移动
    install_http_get() = delete;
    install_http_get(const install_http_get &) = delete;
    install_http_get(install_http_get &&) = delete;
    install_http_get &operator=(const install_http_get &) = delete;
    install_http_get &operator=(install_http_get &&) = delete;
};

// ==================== 响应对象(HTTP.send) ====================

/*
 *@struct install_http_send
 *@brief 把 HTTP::Header_send 映射成 `HTTP.send`
 *
 *@note 这里不复制 Header_send,而是直接引用 JS_HTTP::Send 与 JS_HTTP::Link,
 *       所以脚本里 res.text(...) 之后再 res.send() 能正确发出已改好的响应。
 */
struct install_http_send
{
    inline static JSClassID class_id = 0;

    JS_HTTP &item_cache; ///< 持有 Send / Link
    bool &sent;          ///< 响应是否已经开始发送(由 JS_HTTP::run 持有)
    JSContext *ctx_ = nullptr;
    JSValue obj = JS_UNDEFINED;

    static void ensure_class(JSContext *ctx)
    {
        register_class(JS_GetRuntime(ctx), class_id, "HTTPSend", nullptr);
    }

    template <JSValue (install_http_send::*Func)(JSContext *, JSValueConst, int,
            JSValueConst *)>
    static JSValue trampoline(JSContext *ctx, JSValueConst this_val, int argc,
                              JSValueConst *argv)
    {
        auto *self = static_cast<install_http_send *>(JS_GetOpaque(this_val, class_id));
        if (!self)
            return JS_UNDEFINED;
        return (self->*Func)(ctx, this_val, argc, argv);
    }

    template <JSValue (install_http_send::*Func)(JSContext *, JSValueConst, int,
            JSValueConst *)>
    void bind(const char *name)
    {
        JSValue func = JS_NewCFunction(ctx_, trampoline<Func>, name, 0);
        if (JS_IsException(func))
        {
            Log::error(std::string("JS: cannot create HTTP.send.") + name);
            return;
        }
        if (JS_SetPropertyStr(ctx_, obj, name, func) < 0)
            Log::error(std::string("JS: cannot define HTTP.send.") + name);
    }

    HTTP::Header_send &res() {
        return item_cache.Send;
    }
    TCP::Base_Link &link() {
        return item_cache.Link;
    }

    /*
     *@brief 响应头大小写不敏感查找
     */
    static std::string find_header(const std::map<std::string, std::string> &headers,
                                   const std::string &name)
    {
        const std::string key = HTTP::to_lower(name);
        for (const auto &pair : headers)
        {
            if (HTTP::to_lower(pair.first) == key)
                return pair.second;
        }
        return std::string();
    }

    /*
     *@brief text / html / json 的公共实现
     */
    JSValue reply_with(JSContext *ctx, int argc, JSValueConst *argv, const char *content_type)
    {
        if (argc < 1)
            return JS_ThrowTypeError(ctx, "response body is required");

        std::string text;
        if (!js_value_to_string(ctx, argv[0], text))
            return JS_EXCEPTION;

        if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1]))
        {
            int32_t code = 0;
            if (JS_ToInt32(ctx, &code, argv[1]) < 0)
                return JS_EXCEPTION;
            res().status = code;
        }

        res().set_header("Content-Type", content_type);
        res().body = text;
        return JS_NewStringLen(ctx, text.c_str(), text.size());
    }

    // -------- 状态码 / 响应头 --------

    JSValue status(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        if (argc >= 1 && !JS_IsUndefined(argv[0]) && !JS_IsNull(argv[0]))
        {
            int32_t code = 0;
            if (JS_ToInt32(ctx, &code, argv[0]) < 0)
                return JS_EXCEPTION;
            res().status = code;
        }
        if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1]))
        {
            std::string text;
            if (!js_value_to_string(ctx, argv[1], text))
                return JS_EXCEPTION;
            res().status_text = text;
        }
        return JS_NewInt32(ctx, res().status);
    }

    JSValue header(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        if (argc < 1)
            return JS_ThrowTypeError(ctx, "header(name[, value]) requires a name");

        std::string name;
        if (!js_value_to_string(ctx, argv[0], name))
            return JS_EXCEPTION;

        if (argc < 2)
        {
            const std::string value = find_header(res().headers, name);
            return JS_NewStringLen(ctx, value.c_str(), value.size());
        }

        std::string value;
        if (!js_value_to_string(ctx, argv[1], value))
            return JS_EXCEPTION;
        res().set_header(name, value);
        return JS_NewStringLen(ctx, value.c_str(), value.size());
    }

    JSValue removeHeader(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        if (argc < 1)
            return JS_ThrowTypeError(ctx, "removeHeader(name) requires a name");

        std::string name;
        if (!js_value_to_string(ctx, argv[0], name))
            return JS_EXCEPTION;

        const std::string key = HTTP::to_lower(name);
        bool removed = false;
        for (auto it = res().headers.begin(); it != res().headers.end();)
        {
            if (HTTP::to_lower(it->first) == key)
            {
                it = res().headers.erase(it);
                removed = true;
            }
            else
            {
                ++it;
            }
        }
        return JS_NewBool(ctx, removed);
    }

    // -------- 响应体 --------

    JSValue body(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        if (argc >= 1)
        {
            std::string text;
            if (!js_value_to_string(ctx, argv[0], text))
                return JS_EXCEPTION;
            res().body = std::move(text);
        }
        const std::string &current = res().body;
        return JS_NewStringLen(ctx, current.c_str(), current.size());
    }

    JSValue text(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        return reply_with(ctx, argc, argv, "text/plain; charset=utf-8");
    }

    JSValue html(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        return reply_with(ctx, argc, argv, "text/html; charset=utf-8");
    }

    // -------- 二进制响应 --------

    JSValue binary(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        if (argc < 1)
            return JS_ThrowTypeError(ctx, "binary(data[, status]) requires data");

        std::string data;
        if (!js_value_to_bytes(ctx, argv[0], data))
            return JS_EXCEPTION;

        if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1]))
        {
            int32_t code = 0;
            if (JS_ToInt32(ctx, &code, argv[1]) < 0)
                return JS_EXCEPTION;
            res().status = code;
        }

        // 脚本已指定 Content-Type 时尊重脚本的选择
        if (find_header(res().headers, "Content-Type").empty())
            res().set_header("Content-Type", "application/octet-stream");
        res().body = data;
        return js_new_bytes(ctx, res().body);
    }

    JSValue chunkBinary(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        if (argc < 1)
            return JS_ThrowTypeError(ctx, "chunkBinary(data) requires data");

        std::string data;
        if (!js_value_to_bytes(ctx, argv[0], data))
            return JS_EXCEPTION;

        bool ok = false;
        try
        {
            ok = res().send_chunk(link(), data);
        }
        catch (...)
        {
            ok = false;
        }
        sent = true;
        return JS_NewBool(ctx, ok);
    }

    /*
     *@brief 直接以文件内容响应(定长流式发送,大文件不会整块读进内存)
     *@param path 受 JS::File_policy 约束的文件路径
     *@param type 可选的 Content-Type,缺省按扩展名猜测
     */
    JSValue file(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        if (argc < 1)
            return JS_ThrowTypeError(ctx, "file(path[, contentType]) requires a path");

        std::string raw;
        if (!js_value_to_string(ctx, argv[0], raw))
            return JS_EXCEPTION;

        const auto policy = file_policy_snapshot();

        std::filesystem::path target;
        if (!resolve_file_path(ctx, *policy, raw, File_access::Read, target))
            return JS_EXCEPTION;

        // 读锁覆盖整个发送过程:大文件慢慢发的时候,
        // 同一路径的写操作会等它发完,避免客户端收到写一半的内容
        const auto lock = file_read_lock(target);

        std::error_code ec;
        const auto size = std::filesystem::file_size(target, ec);
        if (ec)
            return JS_ThrowTypeError(ctx, "cannot stat file");

        std::ifstream in(target, std::ios::binary);
        if (!in)
            return JS_ThrowTypeError(ctx, "cannot open file for reading");

        std::string type;
        if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1]))
        {
            if (!js_value_to_string(ctx, argv[1], type))
                return JS_EXCEPTION;
        }
        else
        {
            type = guess_content_type(target);
        }

        if (find_header(res().headers, "Content-Type").empty())
            res().set_header("Content-Type", type);
        // 显式给出 Content-Length:走定长流式,免去分块封装
        res().set_header("Content-Length", std::to_string(size));

        res().body.clear();
        res().streaming = true;
        if (!res().begin_stream(link()))
        {
            sent = true;
            return JS_NewBool(ctx, false);
        }

        std::vector<char> buffer(64u * 1024u);
        bool ok = true;
        while (ok)
        {
            in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            const std::streamsize got = in.gcount();
            if (got <= 0)
                break;
            ok = res().send_chunk(link(), buffer.data(), static_cast<std::size_t>(got));
        }
        if (ok)
            ok = res().end_stream(link());

        sent = true;
        return JS_NewBool(ctx, ok);
    }

    JSValue json(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        if (argc < 1)
            return JS_ThrowTypeError(ctx, "json(value[, status]) requires a value");

        std::string text;
        if (JS_IsString(argv[0]))
        {
            // 已经是字符串:直接当 JSON 文本使用,便于脚本自行拼接
            if (!js_value_to_string(ctx, argv[0], text))
                return JS_EXCEPTION;
        }
        else
        {
            JSValue stringified = JS_JSONStringify(ctx, argv[0], JS_UNDEFINED, JS_UNDEFINED);
            if (JS_IsException(stringified))
                return JS_EXCEPTION;
            if (JS_IsUndefined(stringified))
            {
                // 例如 undefined / function / 循环引用以外的不可序列化值
                JS_FreeValue(ctx, stringified);
                return JS_ThrowTypeError(ctx, "json(value): value is not serializable");
            }
            const bool ok = js_value_to_string(ctx, stringified, text);
            JS_FreeValue(ctx, stringified);
            if (!ok)
                return JS_EXCEPTION;
        }

        if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1]))
        {
            int32_t code = 0;
            if (JS_ToInt32(ctx, &code, argv[1]) < 0)
                return JS_EXCEPTION;
            res().status = code;
        }

        res().set_header("Content-Type", "application/json; charset=utf-8");
        res().body = text;
        return JS_NewStringLen(ctx, text.c_str(), text.size());
    }

    JSValue redirect(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        if (argc < 1)
            return JS_ThrowTypeError(ctx, "redirect(location[, status]) requires a location");

        std::string location;
        if (!js_value_to_string(ctx, argv[0], location))
            return JS_EXCEPTION;

        int32_t code = 302;
        if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1]))
        {
            if (JS_ToInt32(ctx, &code, argv[1]) < 0)
                return JS_EXCEPTION;
        }

        res().status = code;
        res().set_header("Location", location);
        res().body.clear();
        return JS_NewStringLen(ctx, location.c_str(), location.size());
    }

    JSValue cookie(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        if (argc < 1)
            return JS_ThrowTypeError(ctx,
                                     "cookie(Cookie|{name, value, ...}) requires an argument");

        HTTP::Cookie item;
        if (!cookie_from_js(ctx, argv[0], item))
            return JS_EXCEPTION;

        res().add_cookie(item);
        const std::string text = item.to_string();
        return JS_NewStringLen(ctx, text.c_str(), text.size());
    }

    JSValue keepAlive(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        bool enable = true;
        if (argc >= 1)
        {
            const int on = JS_ToBool(ctx, argv[0]);
            if (on < 0)
                return JS_EXCEPTION;
            enable = (on != 0);
        }
        res().keep_alive = enable;
        // 脚本显式指定后即以其为准,不再由框架自动改写
        res().keep_alive_auto = false;
        return JS_NewBool(ctx, enable);
    }

    // -------- 发送 --------

    JSValue send(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        if (sent)
            return JS_NewBool(ctx, false);
        try
        {
            res().send(link());
        }
        catch (const std::exception &e)
        {
            return JS_ThrowInternalError(ctx, "HTTP.send.send failed: %s", e.what());
        }
        catch (...)
        {
            return JS_ThrowInternalError(ctx, "HTTP.send.send failed");
        }
        sent = true;
        return JS_NewBool(ctx, true);
    }

    JSValue sent_(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        return JS_NewBool(ctx, sent);
    }

    JSValue beginStream(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        bool ok = false;
        try
        {
            // 先切到流式模式,否则 send_head 会按定长补 Content-Length 而不是分块
            res().streaming = true;
            ok = res().begin_stream(link());
        }
        catch (...)
        {
            ok = false;
        }
        sent = true; // 头已(尝试)发出,不再回退到 500
        return JS_NewBool(ctx, ok);
    }

    JSValue chunk(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        if (argc < 1)
            return JS_ThrowTypeError(ctx, "chunk(data) requires data");

        std::string data;
        if (!js_value_to_string(ctx, argv[0], data))
            return JS_EXCEPTION;

        bool ok = false;
        try
        {
            ok = res().send_chunk(link(), data);
        }
        catch (...)
        {
            ok = false;
        }
        sent = true;
        return JS_NewBool(ctx, ok);
    }

    JSValue endStream(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        bool ok = false;
        try
        {
            ok = res().end_stream(link());
        }
        catch (...)
        {
            ok = false;
        }
        sent = true;
        return JS_NewBool(ctx, ok);
    }

    /*
     *@brief 关断非法请求:不发送任何字节(状态行 / 响应头 / 正文),直接关闭连接
     *@return true 表示本次调用完成了关闭;响应已经开始发送后调用返回 false(不做事)
     *@note  关闭前先把 sent 置真,避免 JS_HTTP::run() 在脚本结束后补发 500 响应;
     *       关闭走 TCP::Base_Link::Close(),不经过 Header_send,因此对端收不到任何数据
     */
    JSValue fake_close(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        if (sent)
            return JS_NewBool(ctx, false);

        sent = true; // 已"处理"完毕,阻止框架回退 500

        TCP::Base_Link &conn = link();
        bool ok = true;
        try
        {
            Log::access("HTTP.send.fake_close: connection closed without response, "
                        "peer: " + conn.get_peer(), Log::Color::Yellow);
            conn.Close();
        }
        catch (...)
        {
            ok = false;
        }
        return JS_NewBool(ctx, ok);
    }

    install_http_send(JSContext *ctx, JS_HTTP &item, bool &sent_flag):
        item_cache(item), sent(sent_flag), ctx_(ctx)
    {
        ensure_class(ctx);

        obj = JS_NewObjectClass(ctx, class_id);
        if (JS_IsException(obj))
        {
            obj = JS_UNDEFINED;
            Log::error("JS: cannot create HTTP.send object");
            return;
        }

        JS_SetOpaque(obj, this);

        bind<&install_http_send::status>("status");
        bind<&install_http_send::header>("header");
        bind<&install_http_send::removeHeader>("removeHeader");
        bind<&install_http_send::body>("body");
        bind<&install_http_send::text>("text");
        bind<&install_http_send::html>("html");
        bind<&install_http_send::json>("json");
        bind<&install_http_send::binary>("binary");
        bind<&install_http_send::chunkBinary>("chunkBinary");
        bind<&install_http_send::file>("file");
        bind<&install_http_send::redirect>("redirect");
        bind<&install_http_send::cookie>("cookie");
        bind<&install_http_send::keepAlive>("keepAlive");
        bind<&install_http_send::send>("send");
        bind<&install_http_send::sent_>("sent");
        bind<&install_http_send::beginStream>("beginStream");
        bind<&install_http_send::chunk>("chunk");
        bind<&install_http_send::endStream>("endStream");
        bind<&install_http_send::fake_close>("fake_close");

        JSValue global = JS_GetGlobalObject(ctx);
        if (JS_IsException(global))
        {
            Log::error("JS: cannot get global object for HTTP.send");
            return;
        }

        JSValue ns = js_ensure_object(ctx, global, "HTTP");
        if (!JS_IsException(ns))
        {
            if (JS_SetPropertyStr(ctx, ns, "send", JS_DupValue(ctx, obj)) < 0)
                Log::error("JS: cannot define HTTP.send");
            JS_FreeValue(ctx, ns);
        }
        else
        {
            Log::error("JS: cannot create HTTP namespace");
        }
        JS_FreeValue(ctx, global);
    }

    ~install_http_send()
    {
        JS_FreeValue(ctx_, obj);
    }

    install_http_send() = delete;
    install_http_send(const install_http_send &) = delete;
    install_http_send(install_http_send &&) = delete;
    install_http_send &operator=(const install_http_send &) = delete;
    install_http_send &operator=(install_http_send &&) = delete;
};

// ============================================================
// Global(网页脚本侧)
// ============================================================

/*
 *@note 这一组函数只调用 JS:: 的公开接口(global_get/global_set/...),
 *       因此可以放在全局命名空间里,供 JS_HTTP::run / JS_WS::run 直接使用。
 */

JSValue js_global_api_get(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "Global.get(key) requires a key");

    std::string key;
    if (!js_value_to_string(ctx, argv[0], key))
        return JS_EXCEPTION;

    bool found = false;
    const std::string text = JS::global_get(key, found);
    if (!found)
        return JS_UNDEFINED;

    JSValue value = json_parse(ctx, text);
    if (JS_IsException(value))
        return JS_ThrowTypeError(ctx, "Global.get: stored value is not valid JSON");
    return value;
}

JSValue js_global_api_set(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    if (argc < 2)
        return JS_ThrowTypeError(ctx, "Global.set(key, value) requires two arguments");

    std::string key;
    if (!js_value_to_string(ctx, argv[0], key))
        return JS_EXCEPTION;

    std::string text;
    if (!json_stringify(ctx, argv[1], text))
        return JS_ThrowTypeError(ctx, "Global.set: value must be JSON serializable");

    if (!JS::global_set(key, text))
        return JS_ThrowTypeError(ctx, "Global.set: cannot store value");
    return JS_UNDEFINED;
}

JSValue js_global_api_del(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "Global.del(key) requires a key");

    std::string key;
    if (!js_value_to_string(ctx, argv[0], key))
        return JS_EXCEPTION;

    JS::global_del(key);
    return JS_UNDEFINED;
}

JSValue js_global_api_has(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "Global.has(key) requires a key");

    std::string key;
    if (!js_value_to_string(ctx, argv[0], key))
        return JS_EXCEPTION;

    return JS_NewBool(ctx, JS::global_has(key));
}

JSValue js_global_api_keys(JSContext *ctx, JSValueConst, int, JSValueConst *)
{
    const std::vector<std::string> keys = JS::global_keys();

    JSValue array = JS_NewArray(ctx);
    if (JS_IsException(array))
        return array;

    for (uint32_t i = 0; i < keys.size(); ++i)
    {
        JS_SetPropertyUint32(ctx, array, i,
                             JS_NewStringLen(ctx, keys[i].c_str(), keys[i].size()));
    }
    return array;
}

JSValue js_global_api_call(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "Global.call(name[, args]) requires a name");

    std::string name;
    if (!js_value_to_string(ctx, argv[0], name))
        return JS_EXCEPTION;

    // 第二个参数是数组时按数组展开,否则包装成单元素数组;也支持传多个参数
    std::string args_json = "[]";
    if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1]))
    {
        JSValue array = JS_UNDEFINED;
        if (argc == 2 && JS_IsArray(ctx, argv[1]))
        {
            array = JS_DupValue(ctx, argv[1]);
        }
        else
        {
            array = JS_NewArray(ctx);
            if (JS_IsException(array))
                return array;
            for (int i = 1; i < argc; ++i)
            {
                JS_SetPropertyUint32(ctx, array, static_cast<uint32_t>(i - 1),
                                     JS_DupValue(ctx, argv[i]));
            }
        }

        if (!json_stringify(ctx, array, args_json))
        {
            JS_FreeValue(ctx, array);
            return JS_ThrowTypeError(
                       ctx, "Global.call: arguments must be JSON serializable");
        }
        JS_FreeValue(ctx, array);
    }

    std::string error;
    const std::string result_json = JS::global_call(name, args_json, error);
    if (!error.empty())
        return JS_ThrowTypeError(ctx, "Global.call: %s", error.c_str());
    if (result_json.empty())
        return JS_UNDEFINED;

    JSValue value = json_parse(ctx, result_json);
    if (JS_IsException(value))
        return JS_ThrowTypeError(ctx, "Global.call: result is not valid JSON");
    return value;
}

/*
 *@brief 把 Global 对象挂到网页脚本里
 *@note  未配置全局脚本时不暴露 Global,脚本里访问到 undefined 会直接报错
 */
void install_global(JSContext *ctx)
{
    if (!JS::global_running())
        return;

    JSValue global = JS_GetGlobalObject(ctx);
    if (JS_IsException(global))
    {
        Log::error("JS: cannot get global object for Global");
        return;
    }

    JSValue ns = JS_NewObject(ctx);
    if (JS_IsException(ns))
    {
        JS_FreeValue(ctx, global);
        Log::error("JS: cannot create Global object");
        return;
    }

    JS_SetPropertyStr(ctx, ns, "get", JS_NewCFunction(ctx, js_global_api_get, "get", 1));
    JS_SetPropertyStr(ctx, ns, "set", JS_NewCFunction(ctx, js_global_api_set, "set", 2));
    JS_SetPropertyStr(ctx, ns, "del", JS_NewCFunction(ctx, js_global_api_del, "del", 1));
    JS_SetPropertyStr(ctx, ns, "has", JS_NewCFunction(ctx, js_global_api_has, "has", 1));
    JS_SetPropertyStr(ctx, ns, "keys", JS_NewCFunction(ctx, js_global_api_keys, "keys", 0));
    JS_SetPropertyStr(ctx, ns, "call", JS_NewCFunction(ctx, js_global_api_call, "call", 2));

    JS_SetPropertyStr(ctx, global, "Global", ns);
    JS_FreeValue(ctx, global);
}

} // namespace

// ============================================================
// JS_HTTP
// ============================================================

void JS_HTTP::run()
{
    const std::string peer = Link.get_peer();

    // 让 File.* 知道当前是哪个脚本在访问文件,据此匹配文件规则
    // (用作用域守卫:脚本结束后恢复,避免权限上下文泄漏给后续代码)
    Scoped_script script_scope(JS_addr);

    std::string script;
    if (!read_whole_file(JS_addr, script))
    {
        Log::error("JS: cannot open script file: " + JS_addr + " (peer: " + peer + ")");
        // 具体路径只写日志:响应体不回显服务器路径(信息泄漏)
        Send = HTTP::Header_send::Status(500, "Internal Server Error");
        Send.send(Link);
        return;
    }

    JSRuntime *rt = JS_NewRuntime();
    if (!rt)
    {
        Log::error("JS: cannot create runtime for " + JS_addr + " (peer: " + peer + ")");
        Send = HTTP::Header_send::Status(500, "JS runtime init failed");
        Send.send(Link);
        return;
    }
    // 限制脚本可用的内存,避免失控的脚本拖垮整个进程
    apply_memory_limit(rt, Limit_kind::Request);

    JSContext *ctx = JS_NewContext(rt);
    if (!ctx)
    {
        JS_FreeRuntime(rt);
        Log::error("JS: cannot create context for " + JS_addr + " (peer: " + peer + ")");
        Send = HTTP::Header_send::Status(500, "JS context init failed");
        Send.send(Link);
        return;
    }

    bool sent = false;
    bool ok = false;
    std::string error_text;

    {
        // 桥接对象的生命周期必须覆盖整个脚本执行过程
        install_log(ctx);
        install_cookie(ctx);
        install_file(ctx);
        install_sqlite(ctx, rt);
        install_global(ctx);
        install_http_get get_iface(ctx, *this);
        install_http_send send_iface(ctx, *this, sent);
        ok = eval_script(ctx, rt, JS_addr, script, error_text);
    }

    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);

    if (!ok)
    {
        Log::error("JS: script error in " + JS_addr + ": " + one_line(error_text) +
                   " (peer: " + peer + ")");
        if (!sent)
        {
            // 异常堆栈只进日志:响应体里带堆栈会泄漏源码路径与内部结构
            Send = HTTP::Header_send::Status(500, "Internal Server Error");
            Send.send(Link);
        }
        return;
    }

    if (!sent)
    {
        Log::warning("JS: script did not send a response: " + JS_addr + " (peer: " + peer + ")");
        Send = HTTP::Header_send::Status(500, "JS script did not send a response");
        Send.send(Link);
    }
}

// ============================================================
// WebSocket 对象(ws)
// ============================================================

namespace
{

/*
 *@struct install_ws
 *@brief 把 HTTP::WebSocket 映射成全局对象 `ws`
 *
 *@note 与 install_http_send 相同:直接引用调用方的 WebSocket 对象,
 *       脚本执行期间该对象由调用方保证存活。
 */
struct install_ws
{
    inline static JSClassID class_id = 0;

    JS_WS &item_cache;
    JSContext *ctx_ = nullptr;
    JSValue obj = JS_UNDEFINED;
    bool last_binary_ = false; ///< 最近一次 recv 收到的消息是否为二进制

    static void ensure_class(JSContext *ctx)
    {
        register_class(JS_GetRuntime(ctx), class_id, "WS", nullptr);
    }

    template <JSValue (install_ws::*Func)(JSContext *, JSValueConst, int, JSValueConst *)>
    static JSValue trampoline(JSContext *ctx, JSValueConst this_val, int argc,
                              JSValueConst *argv)
    {
        auto *self = static_cast<install_ws *>(JS_GetOpaque(this_val, class_id));
        if (!self)
            return JS_UNDEFINED;
        return (self->*Func)(ctx, this_val, argc, argv);
    }

    template <JSValue (install_ws::*Func)(JSContext *, JSValueConst, int, JSValueConst *)>
    void bind(const char *name)
    {
        JSValue func = JS_NewCFunction(ctx_, trampoline<Func>, name, 0);
        if (JS_IsException(func))
        {
            Log::error(std::string("JS: cannot create ws.") + name);
            return;
        }
        if (JS_SetPropertyStr(ctx_, obj, name, func) < 0)
            Log::error(std::string("JS: cannot define ws.") + name);
    }

    HTTP::WebSocket &ws() {
        return item_cache.Ws;
    }

    JSValue send(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        if (argc < 1)
            return JS_ThrowTypeError(ctx, "ws.send(text) requires a message");

        std::string text;
        if (!js_value_to_string(ctx, argv[0], text))
            return JS_EXCEPTION;
        return JS_NewBool(ctx, ws().SendText(text));
    }

    JSValue sendBinary(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        if (argc < 1)
            return JS_ThrowTypeError(ctx, "ws.sendBinary(data) requires data");

        std::string raw;
        if (!js_value_to_bytes(ctx, argv[0], raw))
            return JS_EXCEPTION;
        std::vector<char> data(raw.begin(), raw.end());
        return JS_NewBool(ctx, ws().SendBinary(data));
    }

    JSValue recv(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        // 不传参数时用配置里的缺省超时(0 表示一直阻塞)
        int32_t timeout_ms = websocket_recv_timeout_ms();
        if (argc >= 1 && !JS_IsUndefined(argv[0]) && !JS_IsNull(argv[0]))
        {
            if (JS_ToInt32(ctx, &timeout_ms, argv[0]) < 0)
                return JS_EXCEPTION;
        }

        std::string msg;
        bool binary = false;
        const HTTP::WebSocket::RecvStatus status = ws().RecvEx(msg, binary, timeout_ms);

        switch (status)
        {
        case HTTP::WebSocket::RecvStatus::Message:
            last_binary_ = binary;
            // 二进制帧按原始字节交给脚本,文本帧仍返回字符串
            if (binary)
                return js_new_bytes(ctx, msg);
            return JS_NewStringLen(ctx, msg.c_str(), msg.size());
        case HTTP::WebSocket::RecvStatus::Timeout:
            return JS_UNDEFINED; // 超时:连接仍然有效
        case HTTP::WebSocket::RecvStatus::Closed:
        case HTTP::WebSocket::RecvStatus::Error:
        default:
            return JS_NULL; // 关闭/错误:脚本据此结束循环
        }
    }

    JSValue lastBinary(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        return JS_NewBool(ctx, last_binary_);
    }

    JSValue close(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        int32_t code = 1000;
        if (argc >= 1 && !JS_IsUndefined(argv[0]) && !JS_IsNull(argv[0]))
        {
            if (JS_ToInt32(ctx, &code, argv[0]) < 0)
                return JS_EXCEPTION;
        }

        std::string reason;
        if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1]))
        {
            if (!js_value_to_string(ctx, argv[1], reason))
                return JS_EXCEPTION;
        }

        ws().Close(static_cast<uint16_t>(code), reason);
        return JS_UNDEFINED;
    }

    JSValue valid(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        return JS_NewBool(ctx, ws().valid());
    }

    JSValue url(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        const std::string &value = item_cache.Header.url;
        return JS_NewStringLen(ctx, value.c_str(), value.size());
    }

    JSValue peer(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        const std::string value = ws().link().get_peer();
        return JS_NewStringLen(ctx, value.c_str(), value.size());
    }

    install_ws(JSContext *ctx, JS_WS &item): item_cache(item), ctx_(ctx)
    {
        ensure_class(ctx);

        obj = JS_NewObjectClass(ctx, class_id);
        if (JS_IsException(obj))
        {
            obj = JS_UNDEFINED;
            Log::error("JS: cannot create ws object");
            return;
        }

        JS_SetOpaque(obj, this);

        bind<&install_ws::send>("send");
        bind<&install_ws::sendBinary>("sendBinary");
        bind<&install_ws::recv>("recv");
        bind<&install_ws::lastBinary>("lastBinary");
        bind<&install_ws::close>("close");
        bind<&install_ws::valid>("valid");
        bind<&install_ws::url>("url");
        bind<&install_ws::peer>("peer");

        JSValue global = JS_GetGlobalObject(ctx);
        if (JS_IsException(global))
        {
            Log::error("JS: cannot get global object for ws");
            return;
        }
        if (JS_SetPropertyStr(ctx, global, "ws", JS_DupValue(ctx, obj)) < 0)
            Log::error("JS: cannot define global ws");
        JS_FreeValue(ctx, global);
    }

    ~install_ws()
    {
        JS_FreeValue(ctx_, obj);
    }

    install_ws() = delete;
    install_ws(const install_ws &) = delete;
    install_ws(install_ws &&) = delete;
    install_ws &operator=(const install_ws &) = delete;
    install_ws &operator=(install_ws &&) = delete;
};

} // namespace

void JS_WS::run()
{
    const std::string peer = Ws.link().get_peer();

    // 让 File.* 知道当前是哪个脚本在访问文件,据此匹配文件规则
    Scoped_script script_scope(JS_addr);

    std::string script;
    if (!read_whole_file(JS_addr, script))
    {
        Log::error("JS: cannot open script file: " + JS_addr + " (peer: " + peer + ")");
        Ws.Close(1011, "script not found");
        return;
    }

    JSRuntime *rt = JS_NewRuntime();
    if (!rt)
    {
        Log::error("JS: cannot create runtime for " + JS_addr + " (peer: " + peer + ")");
        Ws.Close(1011, "runtime init failed");
        return;
    }
    apply_memory_limit(rt, Limit_kind::Request);

    JSContext *ctx = JS_NewContext(rt);
    if (!ctx)
    {
        JS_FreeRuntime(rt);
        Log::error("JS: cannot create context for " + JS_addr + " (peer: " + peer + ")");
        Ws.Close(1011, "context init failed");
        return;
    }

    bool ok = false;
    std::string error_text;

    {
        install_log(ctx);
        install_cookie(ctx);
        install_file(ctx);
        install_sqlite(ctx, rt);
        install_global(ctx);
        install_ws ws_iface(ctx, *this);
        ok = eval_script(ctx, rt, JS_addr, script, error_text);
    }

    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);

    if (!ok)
    {
        Log::error("JS: script error in " + JS_addr + ": " + one_line(error_text) +
                   " (peer: " + peer + ")");
        Ws.Close(1011, "script error");
    }
}

// ============================================================
// 文件访问策略(公开接口)
// ============================================================

namespace JS
{

namespace
{
/*
 *@brief 规范化规则里的目录:相对路径以脚本目录为基准,统一转成绝对路径
 *@note  解析失败的目录直接丢弃(丢弃等于该目录不可访问,保持默认拒绝)
 */
std::vector<std::string> clean_dirs(const std::vector<std::string> &dirs,
                                    const std::string &script_dir,
                                    const std::string &rule, const char *kind)
{
    std::vector<std::string> out;
    for (const std::string &text : dirs)
    {
        if (text.empty())
            continue;

        std::filesystem::path dir = std::filesystem::u8path(text);
        if (!dir.is_absolute())
        {
            // 相对目录以脚本目录为基准,避免随进程当前目录漂移
            if (script_dir.empty())
            {
                Log::warning("JS: file rule " + rule + " dropped " + kind +
                             " directory (relative path without script dir): " + text);
                continue;
            }
            dir = std::filesystem::u8path(script_dir) / dir;
        }

        std::error_code ec;
        const std::filesystem::path canonical =
            std::filesystem::weakly_canonical(dir, ec);
        if (ec || canonical.empty())
        {
            Log::warning("JS: file rule " + rule + " has invalid " + kind +
                         " directory: " + text);
            continue;
        }
        out.push_back(canonical.u8string());
    }
    return out;
}

/*
 *@brief 规范化规则里的数据库路径模式
 *@note  与 clean_dirs 不同:允许绝对路径,并保留 * / ** 通配;
 *       相对路径仍以脚本目录为基准(避免随进程当前目录漂移)
 */
std::vector<std::string> clean_db_patterns(const std::vector<std::string> &patterns,
        const std::string &script_dir,
        const std::string &rule, const char *kind)
{
    std::vector<std::string> out;
    for (const std::string &text : patterns)
    {
        if (text.empty())
            continue;

        std::filesystem::path pattern = std::filesystem::u8path(text);
        if (!pattern.is_absolute())
        {
            if (script_dir.empty())
            {
                Log::warning("JS: sql rule " + rule + " dropped " + kind +
                             " database (relative path without script dir): " + text);
                continue;
            }
            pattern = std::filesystem::u8path(script_dir) / pattern;
        }

        // 只做词法规范化:模式里可能含通配符,不能去访问文件系统
        out.push_back(lower_copy(pattern.lexically_normal().generic_u8string()));
    }
    return out;
}

/*
 *@brief 目录列表拼成一行日志
 */
std::string join_dirs(const std::vector<std::string> &dirs)
{
    std::string out;
    for (const std::string &dir : dirs)
    {
        if (!out.empty())
            out += ", ";
        out += dir;
    }
    return out;
}
} // namespace

/*
 *@brief 从已打开的输入流中读取一整行(行尾的 \r\n / \n 不包含在结果里)
 *@param in   已打开的输入流
 *@param line 输出:读到的整行内容(空行时为空串)
 *@return 读到一行返回 true;流已结束或读取失败返回 false
 */
bool getline(std::istream &in, std::string &line)
{
    line.clear();
    if (!std::getline(in, line))
    {
        line.clear(); // 读失败时不留下半行内容,避免调用方误用
        return false;
    }

    // 文本/二进制模式都可能把 \r 留在行尾,统一在这里去掉
    if (!line.empty() && line.back() == '\r')
        line.pop_back();
    return true;
}

/*
 *@brief 打开文件读取其中一整行(逐行跳到目标行,只占一行内存)
 *@param path  文件路径(按 UTF-8 解释)
 *@param line  输出:读到的整行内容(不含行尾换行符)
 *@param index 行号(从 0 开始)
 *@return 读到该行返回 true;文件打不开或行号超出文件行数返回 false
 */
bool getline(const std::string &path, std::string &line, std::size_t index)
{
    line.clear();
    if (path.empty())
        return false;

    std::ifstream in(std::filesystem::u8path(path), std::ios::binary);
    if (!in.is_open())
        return false;

    for (std::size_t i = 0; i < index; ++i)
    {
        // 必须写全限定名:参数是 std::istream,裸调会因 ADL 把 std::getline 也拉进候选集
        if (!JS::getline(in, line))
        {
            line.clear();
            return false;
        }
    }

    return JS::getline(in, line);
}

void set_file_rules(File_policy policy)
{
    File_policy cleaned;
    cleaned.max_read_size = policy.max_read_size;

    if (!policy.script_dir.empty())
    {
        std::error_code ec;
        const std::filesystem::path dir =
            std::filesystem::weakly_canonical(std::filesystem::u8path(policy.script_dir), ec);
        if (ec || dir.empty())
        {
            Log::warning("JS: invalid script dir for file rules: " + policy.script_dir +
                         ", file access disabled");
        }
        else
        {
            cleaned.script_dir = dir.u8string();
        }
    }

    for (const File_rule &rule : policy.rules)
    {
        const std::string name = normalize_script_text(rule.script);
        if (name.empty())
        {
            Log::warning("JS: file rule with an empty script pattern ignored");
            continue;
        }

        File_rule item;
        item.script = name;
        item.read_dirs = clean_dirs(rule.read_dirs, cleaned.script_dir, name, "read");
        item.write_dirs = clean_dirs(rule.write_dirs, cleaned.script_dir, name, "write");

        // 同一模式重复出现时,后写的覆盖前面的
        auto it = std::find_if(cleaned.rules.begin(), cleaned.rules.end(),
        [&item](const File_rule &other) {
            return other.script == item.script;
        });
        if (it == cleaned.rules.end())
            cleaned.rules.push_back(item);
        else
            *it = item;
    }

    // 完全访问脚本:规范化为绝对路径(与运行时的 current_script_abs 一致)
    for (const std::string &script : policy.full_access_scripts)
    {
        if (script.empty())
            continue;

        std::filesystem::path script_path = std::filesystem::u8path(script);
        if (!script_path.is_absolute())
        {
            if (cleaned.script_dir.empty())
            {
                Log::warning("JS: full access script dropped (relative path without script "
                             "dir): " +
                             script);
                continue;
            }
            script_path = std::filesystem::u8path(cleaned.script_dir) / script_path;
        }

        std::error_code ec;
        const std::filesystem::path canonical =
            std::filesystem::weakly_canonical(script_path, ec);
        if (ec || canonical.empty())
        {
            Log::warning("JS: full access script has an invalid path: " + script);
            continue;
        }
        cleaned.full_access_scripts.push_back(normalize_abs_text(canonical.u8string()));
    }

    // SQL 规则:脚本模式规范化方式与文件规则一致,数据库路径保留绝对路径与通配
    for (const Sql_rule &rule : policy.sql_rules)
    {
        const std::string name = normalize_script_text(rule.script);
        if (name.empty())
        {
            Log::warning("JS: sql rule with an empty script pattern ignored");
            continue;
        }

        Sql_rule item;
        item.script = name;
        item.read_dbs = clean_db_patterns(rule.read_dbs, cleaned.script_dir, name, "read");
        item.write_dbs = clean_db_patterns(rule.write_dbs, cleaned.script_dir, name, "write");

        auto it = std::find_if(cleaned.sql_rules.begin(), cleaned.sql_rules.end(),
        [&item](const Sql_rule &other) {
            return other.script == item.script;
        });
        if (it == cleaned.sql_rules.end())
            cleaned.sql_rules.push_back(item);
        else
            *it = item;
    }

    // 整体替换策略:正在执行的脚本继续用自己那份快照,
    // 之后的请求立即生效
    store_file_policy(cleaned);

    if (cleaned.rules.empty() && cleaned.sql_rules.empty() &&
            cleaned.full_access_scripts.empty())
    {
        Log::log("JS: file access disabled (no rules)");
        return;
    }

    Log::log("JS: file access rules: " + std::to_string(cleaned.rules.size()) +
             ", sql rules: " + std::to_string(cleaned.sql_rules.size()) +
             ", full access scripts: " +
             std::to_string(cleaned.full_access_scripts.size()) +
             ", script dir: " + cleaned.script_dir +
             ", max read size: " + std::to_string(cleaned.max_read_size) + " bytes");
    for (const File_rule &rule : cleaned.rules)
    {
        std::string line = "JS:   rule " + rule.script + ", read: ";
        line += rule.read_dirs.empty() ? "(deny)" : join_dirs(rule.read_dirs);
        line += ", write: ";
        line += rule.write_dirs.empty() ? "(deny)" : join_dirs(rule.write_dirs);
        Log::log(line);
    }
    for (const Sql_rule &rule : cleaned.sql_rules)
    {
        std::string line = "JS:   sql rule " + rule.script + ", read: ";
        line += rule.read_dbs.empty() ? "(deny)" : join_dirs(rule.read_dbs);
        line += ", write: ";
        line += rule.write_dbs.empty() ? "(deny)" : join_dirs(rule.write_dbs);
        Log::log(line);
    }
    for (const std::string &script : cleaned.full_access_scripts)
        Log::log("JS:   full access (file + sqlite): " + script);
}

File_policy get_file_policy()
{
    const auto policy = file_policy_snapshot();
    return policy ? *policy : File_policy();
}

// ============================================================
// 超时配置(公开接口)
// ============================================================

void set_timeouts(const Timeouts &timeouts)
{
    std::lock_guard<std::mutex> lock(g_timeouts_mutex);
    g_timeouts = timeouts;
}

void set_limits(const Limits &limits)
{
    std::lock_guard<std::mutex> lock(g_limits_mutex);
    g_limits = limits;
}

Limits get_limits()
{
    std::lock_guard<std::mutex> lock(g_limits_mutex);
    return g_limits;
}

Timeouts get_timeouts()
{
    std::lock_guard<std::mutex> lock(g_timeouts_mutex);
    return g_timeouts;
}

// ============================================================
// 全局数据维护脚本
// ============================================================

namespace
{
/*
 *@struct Global_state
 *@brief 常驻运行时 + 数据区
 *
 *@note  ctx 只在一个线程里跑(每次访问都先拿 mutex),所以不需要额外的
 *       线程绑定;values 存的是 JSON 文本,取出时可以整体拷一份副本。
 */
struct Global_state
{
    std::mutex mutex;
    JSRuntime *rt = nullptr;
    JSContext *ctx = nullptr;
    std::string path;
    std::map<std::string, std::string> values;
};

Global_state &global_state()
{
    static Global_state state;
    return state;
}

/*
 *@brief 单个数据值的上限(防止脚本把内存吃光)
 */
constexpr std::size_t k_global_value_limit = 8u * 1024u * 1024u;

/*
 *@brief 键名校验:空键无效
 */
bool global_key_ok(const std::string &key, JSContext *ctx, const char *who)
{
    if (!key.empty())
        return true;
    JS_ThrowTypeError(ctx, "%s requires a non-empty key", who);
    return false;
}

/*
 *@brief 写入一个键(调用方必须已持有 mutex)
 *@return false 表示值不可序列化或超过上限
 */
bool global_store_set_nolock(JSContext *ctx, const std::string &key, JSValueConst value)
{
    if (JS_IsUndefined(value))
    {
        global_state().values.erase(key);
        return true;
    }

    std::string text;
    if (!json_stringify(ctx, value, text))
        return false;
    if (text.size() > k_global_value_limit)
        return false;

    global_state().values[key] = std::move(text);
    return true;
}

/*
 *@brief 读取一个键的 JSON 文本(调用方必须已持有 mutex)
 */
std::string global_store_get_nolock(const std::string &key, bool &found)
{
    const auto &values = global_state().values;
    const auto it = values.find(key);
    if (it == values.end())
    {
        found = false;
        return std::string();
    }
    found = true;
    return it->second;
}

/*
 *@brief 把 JSON 文本解析成 JS 值(解析失败时退回为字符串)
 */
JSValue global_value_from_text(JSContext *ctx, const std::string &text)
{
    JSValue value = json_parse(ctx, text);
    if (JS_IsException(value))
    {
        js_exception_text(ctx); // 清掉异常,返回原文
        return JS_NewStringLen(ctx, text.c_str(), text.size());
    }
    return value;
}

// -------- 全局脚本里的 store.* -------
// 全局脚本本身只在 start_global / global_call 的锁内执行,
// 所以这里不再加锁(否则 std::mutex 重入会直接死锁)

JSValue js_store_set(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    if (argc < 2)
        return JS_ThrowTypeError(ctx, "store.set(key, value) requires a key and a value");

    std::string key;
    if (!js_value_to_string(ctx, argv[0], key))
        return JS_EXCEPTION;
    if (!global_key_ok(key, ctx, "store.set"))
        return JS_EXCEPTION;

    if (!global_store_set_nolock(ctx, key, argv[1]))
        return JS_ThrowTypeError(
                   ctx, "store.set: value must be JSON serializable and not too large");
    return JS_NewBool(ctx, true);
}

JSValue js_store_get(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "store.get(key) requires a key");

    std::string key;
    if (!js_value_to_string(ctx, argv[0], key))
        return JS_EXCEPTION;

    bool found = false;
    const std::string text = global_store_get_nolock(key, found);
    if (!found)
        return JS_UNDEFINED;
    return global_value_from_text(ctx, text);
}

JSValue js_store_del(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "store.del(key) requires a key");

    std::string key;
    if (!js_value_to_string(ctx, argv[0], key))
        return JS_EXCEPTION;

    const std::size_t removed = global_state().values.erase(key);
    return JS_NewBool(ctx, removed > 0);
}

JSValue js_store_has(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
{
    if (argc < 1)
        return JS_ThrowTypeError(ctx, "store.has(key) requires a key");

    std::string key;
    if (!js_value_to_string(ctx, argv[0], key))
        return JS_EXCEPTION;

    const auto &values = global_state().values;
    return JS_NewBool(ctx, values.find(key) != values.end());
}

JSValue js_store_keys(JSContext *ctx, JSValueConst, int, JSValueConst *)
{
    const auto &values = global_state().values;
    JSValue array = JS_NewArray(ctx);
    if (JS_IsException(array))
        return array;

    uint32_t index = 0;
    for (const auto &entry : values)
    {
        JS_SetPropertyUint32(ctx, array, index++,
                             JS_NewStringLen(ctx, entry.first.c_str(), entry.first.size()));
    }
    return array;
}

/*
 *@brief 把 store 对象挂到全局脚本里
 */
void install_store(JSContext *ctx)
{
    JSValue global = JS_GetGlobalObject(ctx);
    if (JS_IsException(global))
    {
        Log::error("JS: cannot get global object for store");
        return;
    }

    JSValue store = JS_NewObject(ctx);
    if (JS_IsException(store))
    {
        JS_FreeValue(ctx, global);
        Log::error("JS: cannot create store object");
        return;
    }

    JS_SetPropertyStr(ctx, store, "get", JS_NewCFunction(ctx, js_store_get, "get", 1));
    JS_SetPropertyStr(ctx, store, "set", JS_NewCFunction(ctx, js_store_set, "set", 2));
    JS_SetPropertyStr(ctx, store, "del", JS_NewCFunction(ctx, js_store_del, "del", 1));
    JS_SetPropertyStr(ctx, store, "has", JS_NewCFunction(ctx, js_store_has, "has", 1));
    JS_SetPropertyStr(ctx, store, "keys", JS_NewCFunction(ctx, js_store_keys, "keys", 0));
    JS_SetPropertyStr(ctx, global, "store", store);
    JS_FreeValue(ctx, global);
}

} // namespace

// ============================================================
// 全局数据维护脚本(公开接口)
// ============================================================

bool start_global(const Global_options &options, std::string &error)
{
    error.clear();
    if (options.script_path.empty())
    {
        error = "global script path is empty";
        return false;
    }

    std::string script;
    if (!read_whole_file(options.script_path, script))
    {
        error = "cannot read global script: " + options.script_path;
        return false;
    }

    Global_state &state = global_state();
    std::lock_guard<std::mutex> lock(state.mutex);
    if (state.ctx != nullptr)
    {
        error = "global script is already running: " + state.path;
        return false;
    }

    JSRuntime *rt = JS_NewRuntime();
    if (rt == nullptr)
    {
        error = "cannot create global runtime";
        return false;
    }
    // 全局脚本是常驻的,给宽一点的限额
    apply_memory_limit(rt, Limit_kind::Global);

    JSContext *ctx = JS_NewContext(rt);
    if (ctx == nullptr)
    {
        JS_FreeRuntime(rt);
        error = "cannot create global context";
        return false;
    }

    state.rt = rt;
    state.ctx = ctx;
    state.path = options.script_path;
    state.values.clear();

    // File.* / SQL.* 靠它认出"当前脚本",再按配置授予的规则匹配权限
    Scoped_script script_scope(options.script_path);

    bool ok = false;
    std::string error_text;
    {
        install_log(ctx);
        install_cookie(ctx);
        install_file(ctx);
        install_sqlite(ctx, rt);
        install_store(ctx);
        ok = eval_script(ctx, rt, options.script_path, script, error_text);
    }

    if (!ok)
    {
        Log::error("JS: global script error in " + options.script_path + ": " +
                   one_line(error_text));
        state.ctx = nullptr;
        state.rt = nullptr;
        state.path.clear();
        state.values.clear();
        JS_FreeContext(ctx);
        JS_FreeRuntime(rt);
        error = error_text;
        return false;
    }

    Log::log("JS: global script loaded: " + options.script_path + " (" +
             std::to_string(state.values.size()) + " keys)");
    return true;
}

void stop_global()
{
    Global_state &state = global_state();
    std::lock_guard<std::mutex> lock(state.mutex);
    if (state.ctx == nullptr)
        return;

    JS_FreeContext(state.ctx);
    JS_FreeRuntime(state.rt);
    state.ctx = nullptr;
    state.rt = nullptr;
    state.path.clear();
    state.values.clear();
}

bool global_running()
{
    Global_state &state = global_state();
    std::lock_guard<std::mutex> lock(state.mutex);
    return state.ctx != nullptr;
}

std::string global_script_path()
{
    Global_state &state = global_state();
    std::lock_guard<std::mutex> lock(state.mutex);
    return state.path;
}

bool global_has(const std::string &key)
{
    Global_state &state = global_state();
    std::lock_guard<std::mutex> lock(state.mutex);
    return state.values.find(key) != state.values.end();
}

std::string global_get(const std::string &key, bool &found)
{
    Global_state &state = global_state();
    std::lock_guard<std::mutex> lock(state.mutex);
    return global_store_get_nolock(key, found);
}

bool global_set(const std::string &key, const std::string &json)
{
    if (key.empty() || json.size() > k_global_value_limit)
        return false;

    Global_state &state = global_state();
    std::lock_guard<std::mutex> lock(state.mutex);
    state.values[key] = json;
    return true;
}

bool global_del(const std::string &key)
{
    Global_state &state = global_state();
    std::lock_guard<std::mutex> lock(state.mutex);
    return state.values.erase(key) > 0;
}

std::vector<std::string> global_keys()
{
    Global_state &state = global_state();
    std::lock_guard<std::mutex> lock(state.mutex);

    std::vector<std::string> keys;
    keys.reserve(state.values.size());
    for (const auto &entry : state.values)
        keys.push_back(entry.first);
    return keys;
}

std::string global_call(const std::string &name, const std::string &args_json,
                        std::string &error)
{
    error.clear();

    Global_state &state = global_state();
    std::lock_guard<std::mutex> lock(state.mutex);
    if (state.ctx == nullptr)
    {
        error = "global script is not running";
        return std::string();
    }

    JSContext *ctx = state.ctx;
    JSRuntime *rt = state.rt;

    /*
     * 同步调用全局脚本:执行期间"当前脚本"是全局脚本,但必须在本函数返回时
     * 恢复成调用方(业务)脚本 —— 否则业务脚本在 Global.call 之后调用
     * File.* / Sqlite.open 会按全局脚本的权限规则匹配,等于越权。
     */
    Scoped_script script_scope(state.path);

    /*
     * 全局运行时是在主线程创建的,而 Global.call 由任意请求线程执行。
     * QuickJS 的栈溢出检测依赖创建运行时那一刻记录的栈顶
     * (rt->stack_limit = 创建时栈指针 - 1MB),跨线程时必须按
     * quickjs.h 的约定调用 JS_UpdateStackTop() 刷新。
     * 不刷新时,只要当前请求线程的栈地址低于"创建时栈顶 - 1MB",
     * JSON.parse / JS_Call 内部的栈检查就会误报 stack overflow,
     * 对外表现为 Global.call: invalid arguments JSON。
     */
    JS_UpdateStackTop(rt);

    JSValue global = JS_GetGlobalObject(ctx);
    JSValue func = JS_GetPropertyStr(ctx, global, name.c_str());
    JS_FreeValue(ctx, global);
    if (!JS_IsFunction(ctx, func))
    {
        JS_FreeValue(ctx, func);
        error = "global function not found: " + name;
        return std::string();
    }

    // 参数:JSON 数组 -> JS 数组 -> 展开
    std::vector<JSValue> args;
    JSValue array = json_parse(ctx, args_json.empty() ? std::string("[]") : args_json);
    if (JS_IsException(array))
    {
        /*
         * 不能只报 "invalid arguments JSON":真正的原因可能是
         *   - 全局运行时内存超限(InternalError: out of memory)
         *   - 跨线程栈顶未刷新导致的误报(InternalError: stack overflow)
         *   - 参数里真的出现了非法 JSON
         * 把底层异常和参数长度一起带出来,日志与 500 页面都能直接定位。
         */
        const std::string reason = one_line(js_exception_text(ctx));
        JS_FreeValue(ctx, func);
        error = "invalid arguments JSON (" + std::to_string(args_json.size()) + " bytes)";
        if (!reason.empty() && reason != "unknown error")
        {
            const std::string brief = reason.size() > 200 ? reason.substr(0, 200) : reason;
            error += ": " + brief;
        }
        return std::string();
    }

    uint32_t count = 0;
    {
        JSValue length = JS_GetPropertyStr(ctx, array, "length");
        JS_ToUint32(ctx, &count, length);
        JS_FreeValue(ctx, length);
    }
    if (count > 64)
        count = 64;
    for (uint32_t i = 0; i < count; ++i)
        args.push_back(JS_GetPropertyUint32(ctx, array, i));
    JS_FreeValue(ctx, array);

    std::string result_json;
    {
        Exec_deadline deadline(rt, script_timeout_ms());
        JSValue result = JS_Call(ctx, func, JS_UNDEFINED, static_cast<int>(args.size()),
                                 args.empty() ? nullptr : args.data());
        if (JS_IsException(result))
        {
            error = js_exception_text(ctx);
            if (deadline.expired())
                error = "global function timed out (js_timeout_ms)";
        }
        else if (!JS_IsUndefined(result))
        {
            if (!json_stringify(ctx, result, result_json))
                error = "return value is not JSON serializable";
        }
        JS_FreeValue(ctx, result);
    }

    for (JSValue &value : args)
        JS_FreeValue(ctx, value);
    JS_FreeValue(ctx, func);

    if (!error.empty())
    {
        result_json.clear();
        Log::warning("JS: global call " + name + " failed: " + error);
    }
    return result_json;
}

// ============================================================
// 请求安全检测过滤器
// ============================================================

namespace
{
/*
 *@struct Security_verdict
 *@brief check() 的判定结果
 */
struct Security_verdict
{
    bool block = false;
    bool close = false; ///< 直接断开连接(不发送任何响应)
    int status = 403;
    std::string message = "Forbidden";
    std::vector<std::pair<std::string, std::string>> headers;
};

/*
 *@brief std::map -> 普通 JS 对象
 */
JSValue security_map_to_object(JSContext *ctx,
                               const std::map<std::string, std::string> &src)
{
    JSValue target = JS_NewObject(ctx);
    if (JS_IsException(target))
        return target;

    for (const auto &pair : src)
    {
        JSValue value = JS_NewStringLen(ctx, pair.second.c_str(), pair.second.size());
        if (JS_IsException(value) ||
                JS_SetPropertyStr(ctx, target, pair.first.c_str(), value) < 0)
        {
            JS_FreeValue(ctx, target);
            return JS_EXCEPTION;
        }
    }
    return target;
}

/*
 *@brief 解析 check() 的返回值
 *       undefined/null/true -> 放行;false -> 403;number -> 状态码(-1 表示直接断开连接);
 *       string 非空 -> 403 并作为 message;
 *       {allow,status,message,headers,close} -> 精确控制
 *@return false 表示返回值不合法(调用方按 fail-closed 处理)
 */
bool security_parse_verdict(JSContext *ctx, JSValueConst result, Security_verdict &verdict,
                            std::string &error)
{
    if (JS_IsUndefined(result) || JS_IsNull(result))
        return true;

    if (JS_IsBool(result))
    {
        verdict.block = (JS_ToBool(ctx, result) == 0);
        return true;
    }

    if (JS_IsNumber(result))
    {
        int32_t code = 0;
        if (JS_ToInt32(ctx, &code, result) < 0)
        {
            error = "check(): invalid status code";
            return false;
        }
        // -1:不回应,直接断开连接(用于静默丢弃可疑请求)
        if (code < 0)
        {
            if (code == -1)
            {
                verdict.block = true;
                verdict.close = true;
                return true;
            }

            error = "check(): status code must be -1 or a non-negative HTTP status";
            return false;
        }


        // 2xx/3xx 放行,其余拒绝
        verdict.block = (code < 200 || code >= 400);
        if (verdict.block)
            verdict.status = code;
        return true;
    }

    if (JS_IsObject(result))
    {
        JSValue allow = JS_GetPropertyStr(ctx, result, "allow");
        if (!JS_IsUndefined(allow) && !JS_IsNull(allow) && JS_ToBool(ctx, allow) == 0)
            verdict.block = true;
        JS_FreeValue(ctx, allow);

        JSValue status = JS_GetPropertyStr(ctx, result, "status");
        if (!JS_IsUndefined(status) && !JS_IsNull(status))
        {
            int32_t code = 0;
            if (JS_ToInt32(ctx, &code, status) < 0)
            {
                js_exception_text(ctx);
                error = "check(): invalid status";
                JS_FreeValue(ctx, status);
                return false;
            }
            if (code > 0)
                verdict.status = code;
        }
        JS_FreeValue(ctx, status);

        JSValue close = JS_GetPropertyStr(ctx, result, "close");
        if (!JS_IsUndefined(close) && !JS_IsNull(close) && !JS_IsException(close) &&
                JS_ToBool(ctx, close) != 0)
        {
            verdict.block = true;
            verdict.close = true;
        }
        JS_FreeValue(ctx, close);


        JSValue message = JS_GetPropertyStr(ctx, result, "message");
        if (!JS_IsUndefined(message) && !JS_IsNull(message))
        {
            std::string text;
            if (js_value_to_string(ctx, message, text) && !text.empty())
                verdict.message = text;
        }
        JS_FreeValue(ctx, message);

        JSValue headers = JS_GetPropertyStr(ctx, result, "headers");
        if (!JS_IsUndefined(headers) && !JS_IsNull(headers) && !JS_IsException(headers) &&
                JS_IsObject(headers))
        {
            JSPropertyEnum *tab = nullptr;
            uint32_t len = 0;
            if (JS_GetOwnPropertyNames(ctx, &tab, &len, headers,
                                       JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) == 0)
            {
                for (uint32_t i = 0; i < len; ++i)
                {
                    const char *key = JS_AtomToCString(ctx, tab[i].atom);
                    if (key == nullptr)
                        continue;

                    JSValue item = JS_GetPropertyStr(ctx, headers, key);
                    std::string text;
                    const bool ok = !JS_IsException(item) &&
                                    js_value_to_string(ctx, item, text);
                    if (ok && verdict.headers.size() < 32)
                        verdict.headers.emplace_back(key, text);
                    JS_FreeValue(ctx, item);
                    JS_FreeCString(ctx, key);
                }
                JS_FreePropertyEnum(ctx, tab, len);
            }
        }
        JS_FreeValue(ctx, headers);
        return true;
    }

    // 其它类型(如字符串):非空视为拒绝,便于脚本直接 return "原因"
    if (JS_IsString(result))
    {
        std::string text;
        if (js_value_to_string(ctx, result, text) && !text.empty())
        {
            verdict.block = true;
            verdict.message = text;
        }
        return true;
    }

    error = "check(): return value must be boolean, number, object or undefined";
    return false;
}

/*
 *@struct install_security_request
 *@brief 把 HTTP::Header_get / TCP::Base_Link 映射成只读的 HTTP.get
 *
 *@note   和 install_http_get 不同,这里不借用 JS_HTTP(安全检测器可能独立运行),
 *        直接引用请求头与连接对象;保证作用域覆盖整个 check() 调用。
 */
struct install_security_request
{
    inline static JSClassID class_id = 0;

    const HTTP::Header_get &header;
    TCP::Base_Link &link;
    JSContext *ctx_ = nullptr;
    JSValue obj = JS_UNDEFINED;

    static void ensure_class(JSContext *ctx)
    {
        register_class(JS_GetRuntime(ctx), class_id, "SecurityGet", nullptr);
    }

    template <JSValue (install_security_request::*Func)(JSContext *, JSValueConst, int,
            JSValueConst *)>
    static JSValue trampoline(JSContext *ctx, JSValueConst this_val, int argc,
                              JSValueConst *argv)
    {
        auto *self = static_cast<install_security_request *>(
                         JS_GetOpaque(this_val, class_id));
        if (!self)
            return JS_UNDEFINED;
        return (self->*Func)(ctx, this_val, argc, argv);
    }

    template <JSValue (install_security_request::*Func)(JSContext *, JSValueConst, int,
            JSValueConst *)>
    void bind(const char *name)
    {
        JS_SetPropertyStr(ctx_, obj, name,
                          JS_NewCFunction(ctx_, trampoline<Func>, name, 0));
    }

    static std::string lower(std::string text)
    {
        return HTTP::to_lower(text);
    }

    // -------- 请求信息 --------

    JSValue header_get(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        if (argc < 1)
            return JS_ThrowTypeError(ctx, "header(name) requires a name");

        std::string name;
        if (!js_value_to_string(ctx, argv[0], name))
            return JS_EXCEPTION;

        const std::string value = header.get(name);
        if (value.empty())
            return JS_UNDEFINED;
        return JS_NewStringLen(ctx, value.c_str(), value.size());
    }

    JSValue has_header(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        if (argc < 1)
            return JS_ThrowTypeError(ctx, "hasHeader(name) requires a name");

        std::string name;
        if (!js_value_to_string(ctx, argv[0], name))
            return JS_EXCEPTION;

        const std::string key = lower(name);
        for (const auto &pair : header.headers)
        {
            if (lower(pair.first) == key)
                return JS_NewBool(ctx, true);
        }
        return JS_NewBool(ctx, false);
    }

    JSValue arg(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        if (argc < 1)
            return JS_ThrowTypeError(ctx, "arg(name) requires a name");

        std::string name;
        if (!js_value_to_string(ctx, argv[0], name))
            return JS_EXCEPTION;

        const auto it = header.query.find(name);
        if (it == header.query.end())
            return JS_UNDEFINED;
        return JS_NewStringLen(ctx, it->second.c_str(), it->second.size());
    }

    JSValue has_arg(JSContext *ctx, JSValueConst, int argc, JSValueConst *argv)
    {
        if (argc < 1)
            return JS_ThrowTypeError(ctx, "hasArg(name) requires a name");

        std::string name;
        if (!js_value_to_string(ctx, argv[0], name))
            return JS_EXCEPTION;

        return JS_NewBool(ctx, header.query.find(name) != header.query.end());
    }

    JSValue headers_all(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        return security_map_to_object(ctx, header.headers);
    }

    JSValue args_all(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        return security_map_to_object(ctx, header.query);
    }

    JSValue ip(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        const std::string value = link.get_ip();
        return JS_NewStringLen(ctx, value.c_str(), value.size());
    }

    // -------- 连接安全信息(HTTPS / WSS) --------

    JSValue isHttps(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        return JS_NewBool(ctx, link.is_tls());
    }

    JSValue scheme(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        return JS_NewString(ctx, link.is_tls() ? "https" : "http");
    }

    JSValue tlsProtocol(JSContext *ctx, JSValueConst, int, JSValueConst *)
    {
        const std::string value = link.tls_protocol();
        return JS_NewStringLen(ctx, value.c_str(), value.size());
    }

    install_security_request(JSContext *ctx, const HTTP::Header_get &header,
                             TCP::Base_Link &link)
        : header(header), link(link), ctx_(ctx)
    {
        ensure_class(ctx);

        obj = JS_NewObjectClass(ctx, class_id);
        if (JS_IsException(obj))
        {
            obj = JS_UNDEFINED;
            Log::error("JS: cannot create security request object");
            return;
        }
        JS_SetOpaque(obj, this);

        JS_SetPropertyStr(ctx, obj, "method",
                          JS_NewStringLen(ctx, header.method.c_str(), header.method.size()));
        JS_SetPropertyStr(ctx, obj, "url",
                          JS_NewStringLen(ctx, header.url.c_str(), header.url.size()));
        JS_SetPropertyStr(ctx, obj, "path",
                          JS_NewStringLen(ctx, header.url.c_str(), header.url.size()));
        JS_SetPropertyStr(ctx, obj, "version",
                          JS_NewStringLen(ctx, header.version.c_str(),
                                          header.version.size()));
        JS_SetPropertyStr(ctx, obj, "headers", security_map_to_object(ctx, header.headers));
        JS_SetPropertyStr(ctx, obj, "args", security_map_to_object(ctx, header.query));

        bind<&install_security_request::header_get>("header");
        bind<&install_security_request::has_header>("hasHeader");
        bind<&install_security_request::arg>("arg");
        bind<&install_security_request::has_arg>("hasArg");
        bind<&install_security_request::headers_all>("headersAll");
        bind<&install_security_request::args_all>("argsAll");
        bind<&install_security_request::ip>("ip");
        bind<&install_security_request::isHttps>("isHttps");
        bind<&install_security_request::scheme>("scheme");
        bind<&install_security_request::tlsProtocol>("tlsProtocol");

        JSValue global = JS_GetGlobalObject(ctx);
        if (JS_IsException(global))
        {
            Log::error("JS: cannot get global object for security request");
            return;
        }

        JSValue ns = js_ensure_object(ctx, global, "HTTP");
        if (!JS_IsException(ns))
        {
            if (JS_SetPropertyStr(ctx, ns, "get", JS_DupValue(ctx, obj)) < 0)
                Log::error("JS: cannot define HTTP.get for security script");
            JS_FreeValue(ctx, ns);
        }
        JS_FreeValue(ctx, global);
    }

    ~install_security_request()
    {
        JS_FreeValue(ctx_, obj);
    }

    install_security_request(const install_security_request &) = delete;
    install_security_request &operator=(const install_security_request &) = delete;
    install_security_request(install_security_request &&) = delete;
    install_security_request &operator=(install_security_request &&) = delete;
};

} // namespace

/*
 *@class Security_filter
 *@brief 用一个外部 JS 脚本完成请求判定
 *
 *@note  每次请求起一个独立的 JSRuntime/JSContext(与 HTTP 脚本同一模型),
 *       脚本必须定义 check();脚本抛异常、超时或未定义 check() 时按
 *       fail-closed 处理(500),绝不把异常当成"放行"。
 */
class Security_filter : public HTTP::RequestFilter
{
public:
    explicit Security_filter(std::string path): script_path_(std::move(path)) {}

    HTTP::FilterAction inspect(HTTP::Header_get &request, TCP::Base_Link &link,
                               HTTP::Header_send &response) override;

    std::string script_path() const {
        return script_path_;
    }

private:
    std::string script_path_;
};

// ============================================================
// 安全检测过滤器实现
// ============================================================

namespace
{
/*
 *@brief 读取安全检测脚本
 */
bool load_security_script(const std::string &path, std::string &script, std::string &error)
{
    if (!read_whole_file(path, script))
    {
        error = "cannot read security script: " + path;
        return false;
    }
    if (script.empty())
    {
        error = "security script is empty: " + path;
        return false;
    }
    return true;
}

/*
 *@brief 写入一个纯文本错误响应
 */
void security_error_response(HTTP::Header_send &response, int status,
                             const std::string &text)
{
    response.status = status;
    response.set_header("Content-Type", "text/plain; charset=utf-8");
    response.body = text;
}

} // namespace

HTTP::FilterAction Security_filter::inspect(HTTP::Header_get &request, TCP::Base_Link &link,
        HTTP::Header_send &response)
{
    std::string script;
    std::string error;
    if (!load_security_script(script_path_, script, error))
    {
        Log::error("JS: security filter: " + error);
        security_error_response(response, 500, "security filter unavailable");
        return HTTP::FilterAction::Block;
    }

    JSRuntime *rt = JS_NewRuntime();
    if (rt == nullptr)
    {
        Log::error("JS: security filter: cannot create runtime");
        security_error_response(response, 500, "security filter unavailable");
        return HTTP::FilterAction::Block;
    }
    apply_memory_limit(rt, Limit_kind::Security);

    JSContext *ctx = JS_NewContext(rt);
    if (ctx == nullptr)
    {
        JS_FreeRuntime(rt);
        Log::error("JS: security filter: cannot create context");
        security_error_response(response, 500, "security filter unavailable");
        return HTTP::FilterAction::Block;
    }

    HTTP::FilterAction action = HTTP::FilterAction::Continue;

    {
        // 先登记当前脚本:File / Sqlite 靠它匹配配置里按脚本授予的权限规则
        // (作用域守卫:check() 返回后自动恢复,不会把安全脚本的权限上下文
        //  留给后续的业务脚本)
        Scoped_script script_scope(script_path_);

        // 安全脚本拿到日志、只读请求对象与 File / Sqlite(没有 HTTP.send,
        // 无法自行发送响应);文件 / SQL 权限与业务脚本一样由配置文件授予
        install_log(ctx);
        install_file(ctx);
        install_sqlite(ctx, rt);
        install_security_request request_iface(ctx, request, link);

        std::string error_text;
        if (!eval_script(ctx, rt, script_path_, script, error_text))
        {
            Log::error("JS: security script error in " + script_path_ + ": " +
                       one_line(error_text));
            security_error_response(response, 500, "security filter error");
            action = HTTP::FilterAction::Block;
        }
        else
        {
            JSValue global = JS_GetGlobalObject(ctx);
            JSValue func = JS_GetPropertyStr(ctx, global, "check");
            JS_FreeValue(ctx, global);

            if (!JS_IsFunction(ctx, func))
            {
                Log::error("JS: security script " + script_path_ +
                           " does not define check()");
                security_error_response(response, 500, "security filter error");
                action = HTTP::FilterAction::Block;
            }
            else
            {
                JSValue arg = JS_DupValue(ctx, request_iface.obj);
                JSValue result = JS_Call(ctx, func, JS_UNDEFINED, 1, &arg);
                JS_FreeValue(ctx, arg);

                if (JS_IsException(result))
                {
                    const std::string text = js_exception_text(ctx);
                    Log::error("JS: security check() threw in " + script_path_ + ": " +
                               one_line(text));
                    security_error_response(response, 500, "security filter error");
                    action = HTTP::FilterAction::Block;
                }
                else
                {
                    Security_verdict verdict;
                    if (!security_parse_verdict(ctx, result, verdict, error))
                    {
                        Log::error("JS: security filter: " + error);
                        security_error_response(response, 500, "security filter error");
                        action = HTTP::FilterAction::Block;
                    }
                    else if (verdict.close)
                    {
                        // 安全脚本要求静默丢弃:不回任何响应,直接断开
                        action = HTTP::FilterAction::Close;
                    }

                    else if (verdict.block)
                    {
                        response.status = verdict.status;
                        for (const auto &pair : verdict.headers)
                            response.set_header(pair.first, pair.second);
                        response.set_header("Content-Type", "text/plain; charset=utf-8");
                        response.body = verdict.message;
                        action = HTTP::FilterAction::Block;
                    }
                    else
                    {
                        action = HTTP::FilterAction::Continue;
                    }
                    JS_FreeValue(ctx, result);
                }
                JS_FreeValue(ctx, func);
            }
        }
    }

    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
    return action;
}

std::shared_ptr<HTTP::RequestFilter> make_security_filter(const std::string &script_path,
        std::string &error)
{
    error.clear();
    if (script_path.empty())
    {
        error = "security script path is empty";
        return nullptr;
    }

    std::error_code ec;
    if (!std::filesystem::is_regular_file(std::filesystem::u8path(script_path), ec))
    {
        error = "security script not found: " + script_path;
        return nullptr;
    }
    return std::make_shared<Security_filter>(script_path);
}

} // namespace JS
