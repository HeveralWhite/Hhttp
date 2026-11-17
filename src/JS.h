#ifndef JS_H
#define JS_H

#include <cstddef>
#include <istream>
#include <memory>
#include <string>
#include <vector>

#include <quickjs.h>
#include <sqlite3.h>

#include "HTTP.h"
#include "TCP.h"

/*
 *@namespace JS
 *@brief 脚本执行环境的 C++ 侧配置
 */
namespace JS
{

/*
 *@struct File_rule
 *@brief 一条"脚本 -> 允许访问的目录"规则
 *
 *@note  script 是按脚本目录(--dir)书写的相对路径模式,匹配时不区分大小写:
 *         "index.js"      精确匹配一个脚本
 *         "api/*.js"      * 匹配任意字符但不跨目录
 *         "api/**"        ** 跨目录匹配
 *         "*"             兜底规则(精确匹配 > 其它通配规则 > 兜底)
 *       read_dirs / write_dirs 是允许读取 / 写入的目录列表,留空表示该方向
 *       直接拒绝;两个方向相互独立,可以只给其中一个,也可以指向不同目录。
 *       目录在 set_file_rules 中统一规范化成绝对路径。
 */
struct File_rule
{
    std::string script;                 ///< 脚本匹配模式(相对 --dir,空模式无效)
    std::vector<std::string> read_dirs; ///< 允许读取的目录(空表示禁止读)
    std::vector<std::string> write_dirs;///< 允许写入的目录(空表示禁止写)
};

/*
 *@struct Sql_rule
 *@brief 一条"脚本 -> 允许打开的数据库"规则
 *
 *@note  script 的写法与 File_rule::script 相同(相对 --dir,支持 * / **);
 *       read_dbs / write_dbs 是数据库文件的路径模式,相对路径以 --dir 为基准,
 *       也可以写绝对路径(如 "C:/data/app.db"),同样支持通配,不区分大小写。
 *       只读打开只需要 read_dbs;读写打开需要 write_dbs(写权限包含读权限)。
 *       两个列表都为空表示该脚本没有任何 SQL 权限。
 */
struct Sql_rule
{
    std::string script;                 ///< 脚本匹配模式(相对 --dir,空模式无效)
    std::vector<std::string> read_dbs;  ///< 允许只读打开的数据库(空表示禁止)
    std::vector<std::string> write_dbs; ///< 允许读写的数据库(空表示禁止)
};

/*
 *@struct File_policy
 *@brief 脚本文件访问策略:每条规则只对匹配到的脚本生效
 *
 *@note  规则列表为空表示完全禁用文件功能(默认)。脚本传入的路径统一按
 *       "相对 --dir"解释,`..`、绝对路径、盘符路径一律拒绝;解析时会消解
 *       符号链接,再确认目标仍落在该脚本允许的目录之内。
 *
 *       full_access_scripts 里列出的脚本不受上述限制:可以直接读写任意路径
 *       (包括 "C:/..." 这样的绝对路径与含 `..` 的路径),其 SQL 访问也不受
 *       sql_rules 约束。这是默认关闭的高危能力,由配置文件显式指定。
 */
struct File_policy
{
    std::string script_dir;                         ///< 脚本目录(规则模式的基准,绝对路径)
    std::vector<File_rule> rules;                   ///< 脚本级访问规则
    std::vector<Sql_rule> sql_rules;                ///< SQL 访问规则(空表示禁用 SQLite)
    std::vector<std::string> full_access_scripts;   ///< 完全访问脚本(规范化绝对路径,小写)
    std::size_t max_read_size = 8u * 1024u * 1024u; ///< 单次读取上限(字节,0 表示不限制)
};

/*
 *@brief 设置文件访问策略(进程级,影响之后创建的所有 JS 上下文)
 */
void set_file_rules(File_policy policy);

/*
 *@brief 读取当前文件访问策略
 */
File_policy get_file_policy();

/*
 *@brief 从已打开的输入流中读取一整行(行尾的 \r\n / \n 不包含在结果里)
 *@param in   已打开的输入流(文本模式、二进制模式均可)
 *@param line 输出:读到的整行内容(空行时为空串)
 *@return 读到一行返回 true;流已结束或读取失败返回 false
 *@note  空行同样返回 true,所以不能用 line.empty() 判断是否读完;
 *       Windows 的 \r\n 会把行尾的 \r 去掉,不会残留到结果里;
 *       只读取一行,不会把整个文件读进内存
 */
bool getline(std::istream &in, std::string &line);

/*
 *@brief 打开文件读取其中一整行
 *@param path  文件路径
 *@param line  输出:读到的整行内容(不含行尾换行符)
 *@param index 行号(从 0 开始,默认读第一行)
 *@return 读到该行返回 true;文件打不开或行号超出文件行数返回 false
 *@note  逐行跳到目标行,只占一行内存;路径含非 ASCII 字符时按 UTF-8 处理;
 *       这是脚本层 File.getline(path[, index]) 的底层实现(脚本侧还要先过
 *       JS::set_file_rules 的目录与权限校验)
 */
bool getline(const std::string &path, std::string &line, std::size_t index = 0);

/*
 *@struct Timeouts
 *@brief 进程级超时配置(单位:毫秒,0 表示不限制)
 *
 *@note  js_exec_ms       单次脚本执行超时。作用于 HTTP / WebSocket 脚本、
 *                       安全检测脚本与全局数据脚本;超时通过 quickjs 的
 *                       中断处理器打断脚本,执行结束后立即销毁运行时;
 *       websocket_recv_ms  ws.recv() 不传参数时的缺省收包超时。
 */
struct Timeouts
{
    int js_exec_ms = 0;        ///< 脚本单次执行超时(0 表示不限制)
    int websocket_recv_ms = 0; ///< ws.recv() 缺省超时(0 表示一直阻塞)
};

/*
 *@brief 设置超时配置(进程级,影响之后创建的所有 JS 运行时)
 */
void set_timeouts(const Timeouts &timeouts);

/*
 *@brief 读取当前超时配置
 */
Timeouts get_timeouts();

/*
 *@struct Limits
 *@brief 进程级内存限制(单位:字节,0 表示不限制)
 *
 *@note  三类脚本的运行时是分别创建的,所以内存上限也分别配置:
 *       request_bytes  HTTP / WebSocket 业务脚本(每个请求新建运行时);
 *       security_bytes 安全检测脚本(每个请求新建运行时,同样需要防失控);
 *       global_bytes   全局数据脚本(进程内常驻的唯一运行时)。
 *       这些数值最终交给 quickjs 的 JS_SetMemoryLimit,超出时脚本内的
 *       内存申请会失败(表现为脚本异常,按各入口的 fail-closed 规则处理)。
 */
struct Limits
{
    std::size_t request_bytes = 64u * 1024u * 1024u;  ///< 业务脚本内存上限(0 表示不限制)
    std::size_t security_bytes = 64u * 1024u * 1024u; ///< 安全检测脚本内存上限(0 表示不限制)
    std::size_t global_bytes = 128u * 1024u * 1024u;  ///< 全局数据脚本内存上限(0 表示不限制)
};

/*
 *@brief 设置内存限制(进程级,影响之后创建的所有 JS 运行时)
 */
void set_limits(const Limits &limits);

/*
 *@brief 读取当前内存限制
 */
Limits get_limits();

/*
 *@struct Global_options
 *@brief 全局数据维护脚本的装载参数
 */
struct Global_options
{
    std::string script_path; ///< 全局脚本路径(配置层已解析成绝对路径)
};

/*
 *@brief 装载全局数据维护脚本(常驻一个 JSRuntime/JSContext)
 *@param options 脚本路径
 *@param error   失败原因
 *@return 成功返回 true
 *@note  全局脚本的文件 / SQLite 权限与业务脚本一样由配置文件授予:
 *       base_msg.js_global_script 写成对象时按 js_read_rule / js_write_rule /
 *       js_sql_*_rule / js_full_access 生效;写成字符串时沿用旧版本行为
 *       (配置层把该脚本加入 full_access_scripts,拥有完全访问权限)
 */
bool start_global(const Global_options &options, std::string &error);

/*
 *@brief 卸载全局数据脚本(释放常驻运行时)
 */
void stop_global();

/*
 *@brief 全局数据脚本是否已就绪
 */
bool global_running();

/*
 *@brief 全局脚本的绝对路径(未装载时为空)
 */
std::string global_script_path();

/*
 *@brief 全局数据区:是否存在指定键
 */
bool global_has(const std::string &key);

/*
 *@brief 全局数据区:读取一个键的值(JSON 文本)
 *@param found 是否命中
 */
std::string global_get(const std::string &key, bool &found);

/*
 *@brief 全局数据区:写入一个键(JSON 文本)
 */
bool global_set(const std::string &key, const std::string &json);

/*
 *@brief 全局数据区:删除一个键
 */
bool global_del(const std::string &key);

/*
 *@brief 全局数据区:列出全部键名
 */
std::vector<std::string> global_keys();

/*
 *@brief 调用全局脚本里定义的函数
 *@param name      函数名
 *@param args_json 参数数组的 JSON 文本(形如 "[1,2]")
 *@param error     失败原因(非空表示调用失败)
 *@return 返回值的 JSON 文本;空串表示函数返回 undefined
 */
std::string global_call(const std::string &name, const std::string &args_json,
                        std::string &error);

/*
 *@brief 创建"请求安全检测"过滤器(由外部 JS 脚本完成判定)
 *@param script_path 检测脚本路径(配置层已解析成绝对路径)
 *@param error       失败原因
 *@return 过滤器;失败返回空指针
 *@note  脚本需定义 check() 函数: true/undefined 放行,false 返回 403,
 *       number 作为状态码,-1 表示直接关断连接(不回任何字节),
 *       {allow,status,message,headers,close} 精确控制;
 *       脚本异常或超时按 fail-closed 处理(回 500 并记录日志)
 *
 *       检测脚本的执行环境: console.* 日志、只读请求对象 HTTP.get,
 *       以及与业务脚本相同的 File / Sqlite(权限由 base_msg.js_security_script
 *       配置:字符串写法没有任何文件 / SQL 权限,对象写法则按 roter 字段授予);
 *       没有 HTTP.send,检测脚本不能自行发送响应
 */
std::shared_ptr<HTTP::RequestFilter> make_security_filter(const std::string &script_path,
        std::string &error);

} // namespace JS

/*
 *@class JS_HTTP
 *@brief 用一个外部 JS 脚本处理一次 HTTP 请求(构造即执行)
 *
 *       脚本中可用的环境:
 *         HTTP.get    请求对象: method() url() rawUrl() version() query() headers()
 *                     header(name) cookies() cookie(name) body() bodyBytes() peer() ip()
 *                     isHttps()      当前连接是否 HTTPS(启用 TLS)
 *                     scheme()       "https" / "http"
 *                     tlsProtocol()  协商出的 TLS 版本(如 "TLS 1.3"),非 TLS 返回 ""
 *         HTTP.send   响应对象: status(code[, text]) header(name[, value])
 *                     removeHeader(name) body(text) text(...) html(...) json(...)
 *                     binary(data[, status]) chunkBinary(data) file(path[, type])
 *                     redirect(location[, status]) cookie(Cookie|object)
 *                     keepAlive(enable) beginStream() chunk(data) endStream()
 *                     fake_close()  立即断开连接:不发送状态行/响应头/正文
 *                                    (用于关断非法/可疑请求,对端收不到任何字节)
 *                     send() sent()
 *         Global      全局数据(需配置文件装载全局脚本,否则不存在):
 *                     get(key) set(key, value) del(key) has(key) keys()
 *                     call(name[, args])  调用全局脚本里的函数(同步,跨运行时)
 *                     值的传递走 JSON 文本,不能传函数/循环引用
 *         File        文件读写(范围由 C++ 侧的 JS::set_file_rules 按脚本配置):
 *                     read(path[, start[, end]]) readText(path[, start[, end]])
 *                     getline(path[, index])
 *                     write(path, data)
 *                     append(path, data) exists(path) size(path) list([path])
 *                     remove(path) mkdir(path) root() roots() canRead() canWrite()
 *                     path 按"相对 --dir"解释,必须落在允许目录内(不接受绝对路径与 ..);
 *                     list() 不传参时列出第一条读目录;
 *                     read/readText 的 start/end 是字节偏移(非负整数),
 *                     读取半开区间 [start, end);end 省略表示读到文件末尾;
 *                     越界或 end < start 会抛 RangeError,
 *                     max_read_size 只约束本次实际读取的字节数,因此大文件也能分段读;
 *                     注意区间可能切断多字节字符,文本读取请自行对齐边界;
 *                     getline 读第 index 行(从 0 开始,缺省 0),结果不含行尾的
 *                     \r\n / \n;空行返回 "",行号越界或空文件返回 null
 *                     (所以用返回值是否为 null 判断是否读完),index 按 Number 截断取整
 *                     (NaN 视作 0、1.9 当作 1、true 当作 1),截断后为负数抛 RangeError;
 *                     单行字节数超过 max_read_size 抛错(大文件边读边校验,
 *                     不会先为超长行分配内存);实现逐行跳到目标行,
 *                     只占一行内存,不会把整个文件读进来;
 *                     read/exists/size/list 只看读目录,write/append/remove/mkdir
 *                     只看写目录,两个方向互不越界;
 *                     data 参数可以是字符串、Uint8Array/ArrayBuffer,
 *                     read() 返回 Uint8Array,list() 返回字符串数组
 *                     被配置为 full_access 的脚本不受目录限制,可传任意绝对路径;
 *                     全局数据脚本与安全检测脚本同样适用,权限由
 *                     base_msg.js_global_script / js_security_script 授予
 *         Sqlite      SQLite3 支持(需要 js_sql_read_rule / js_sql_write_rule 或 full_access):
 *                     Sqlite.open(path[, {readonly: true}])  打开数据库,返回数据库对象
 *                     db.exec(sql)                  执行一段(可多条)SQL,返回 true
 *                     db.run(sql, ...params)        执行写语句,返回 {changes, lastInsertRowid}
 *                     db.query(sql, ...params)      查询,返回行数组(数组上的 columns 为列名)
 *                     db.close()                    关闭连接(幂等,脚本结束也会自动关闭)
 *                     db.path() db.changes() db.lastInsertRowid() db.busyTimeout(ms)
 *                     参数支持 null / boolean / number / string / Uint8Array(存为 BLOB);
 *                     未被授权时全局对象 Sqlite 不存在(默认完全关闭);
 *                     全局数据脚本与安全检测脚本同样适用,权限由
 *                     base_msg.js_global_script / js_security_script 授予
 *         Cookie      new Cookie(name, value),属性: name value path domain
 *                     expires maxAge secure httpOnly sameSite,方法: toString()
 *         console.*   以及同名的全局函数 log / debug / warn / error / access,
 *                     统一转交给框架日志(Log::log / Log::debug / ...)
 *
 *       示例脚本:
 *         const req = HTTP.get, res = HTTP.send;
 *         log(req.method(), req.url(), req.query().name || "");
 *         res.json({ok: true, body: req.body()}, 200);
 *         res.send();
 *
 *@note  每次请求新建一个 JSRuntime/JSContext,脚本之间完全隔离;
 *       脚本抛异常或未调用 send() 时框架回 500(异常堆栈同时写入日志);
 *       调用 HTTP.send.fake_close() 断开连接后框架不再补发任何响应(包括 500 回退)
 */
class JS_HTTP
{
public:
    /*
     *@param js_addr JS 脚本文件路径
     *@param link 当前连接
     *@param header 已解析的请求
     */
    JS_HTTP(const std::string &js_addr, TCP::Base_Link &link, const HTTP::Header_get &header):
        JS_addr(js_addr), Link(link), Header(header)
    {
        run();
    }

    ~JS_HTTP() = default;

    JS_HTTP() = delete;
    JS_HTTP(const JS_HTTP &) = delete;
    JS_HTTP(JS_HTTP &&) = delete;
    JS_HTTP &operator=(const JS_HTTP &) = delete;
    JS_HTTP &operator=(JS_HTTP &&) = delete;

    std::string JS_addr;
    TCP::Base_Link Link;
    HTTP::Header_get Header;
    HTTP::Header_send Send;

private:
    /*
     *@brief 加载脚本并执行,负责把脚本结果落到连接上
     */
    void run();
};

/*
 *@class JS_WS
 *@brief 用一个外部 JS 脚本处理一条 WebSocket 连接(构造即执行)
 *
 *       脚本中可用的环境:
 *         ws.send(text)              发送文本消息
 *         ws.sendBinary(data)        发送二进制消息(字符串 / Uint8Array / ArrayBuffer)
 *         ws.recv([timeout_ms])      收一条消息: 文本为字符串、二进制为 Uint8Array,
 *                                    undefined(超时) / null(关闭)
 *         ws.lastBinary()            最近一次 recv 的消息是否为二进制帧
 *         ws.close([code[, reason]]) 发送关闭帧
 *         ws.valid()                 连接是否仍然可用
 *         ws.url() / ws.peer()       握手请求的路径 / 对端 IP:端口
 *         File / Sqlite              同 JS_HTTP(权限同样由 C++ 侧按脚本配置)
 *         Global                     同 JS_HTTP(get/set/del/has/keys/call)
 *         console.*                  同 JS_HTTP
 *
 *       示例脚本:
 *         ws.send("welcome");
 *         while (ws.valid()) {
 *             const msg = ws.recv(1000);          // 1 秒超时
 *             if (msg === undefined) continue;    // 空闲,可以在这里做推送
 *             if (msg === null) break;            // 对端关闭
 *             if (ws.lastBinary()) ws.sendBinary(msg);    // 二进制:Uint8Array 原样回送
 *             else ws.send("echo: " + msg);                // 文本:字符串
 *         }
 *
 *@note  脚本返回(或抛异常)后框架关闭连接;抛异常时以 1011 关闭并记录日志
 */
class JS_WS
{
public:
    /*
     *@param js_addr JS 脚本文件路径
     *@param ws 握手完成的 WebSocket 连接
     *@param header 升级请求(生命周期由调用方保证)
     */
    JS_WS(const std::string &js_addr, HTTP::WebSocket &ws, const HTTP::Header_get &header):
        JS_addr(js_addr), Ws(ws), Header(header)
    {
        run();
    }

    ~JS_WS() = default;

    JS_WS() = delete;
    JS_WS(const JS_WS &) = delete;
    JS_WS(JS_WS &&) = delete;
    JS_WS &operator=(const JS_WS &) = delete;
    JS_WS &operator=(JS_WS &&) = delete;

    std::string JS_addr;
    HTTP::WebSocket &Ws;
    const HTTP::Header_get &Header;

private:
    /*
     *@brief 加载脚本并执行,脚本返回后由框架关闭连接
     */
    void run();
};

#endif // JS_H
