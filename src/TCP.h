#ifndef TCP_H
#define TCP_H

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <cstdint>

/*
 * 跨平台 TCP 层
 *
 * 底层由 Boost.Asio 驱动（Windows 上用 IOCP，Linux/macOS 上用 epoll/kqueue），
 * 但对外仍然是"阻塞式"接口：每个连接由调用方线程（Distributor 的工作线程）
 * 顺序使用，读/写各自返回后立即有结果。这样做是因为上层（HTTP / WebSocket /
 * QuickJS 脚本）本质是同步模型：脚本里的 ws.recv() 必须能"停下来等消息"。
 *
 * 线程模型：
 *   - 一个进程级 io_context 线程池负责所有 socket 的异步读写与 TLS 握手；
 *   - Session 内部维护接收队列，工作线程通过条件变量从这里阻塞取数据；
 *   - Close() / 超时 / 对端断开都通过取消 + 唤醒统一处理，不再依赖
 *     "另一线程直接 shutdown 套接字"这种与 Asio 线程安全规则冲突的做法。
 */

// 前向声明：TLS 上下文的完整定义在 TLS.h 中
// （避免 TCP 层暴露 OpenSSL / Asio 的头文件）
namespace TLS
{
class Context;
}

namespace TCP
{
/*
 *@enum ReadStatus
 *@brief 有界读取的返回状态(见 Base_Link::Read_until)
 */
enum class ReadStatus
{
    Ok,      ///< 已找到结束标志
    Timeout, ///< 等待超时
    Closed,  ///< 连接已被关闭或出错
    Overflow ///< 累积长度超过 max_bytes(可能为攻击,建议直接断连接)
};

namespace detail
{
class Session; ///< 一条连接的真实 I/O 会话(定义在 TCP.cpp)
}

/*
 *@class Base_Link
 *@brief TCP连接的基本类，提供发送和接收功能。
 *       同一个对象既可以承载明文 TCP,也可以承载一条已完成 TLS 握手的连接;
 *       是 TLS 连接时,收发字节由 TLS 层自动加解密,上层代码无需区分。
 *
 *@note  Base_Link 是可拷贝的"句柄"：拷贝出来的对象共享同一条连接与同一份
 *       收发状态，最后一个副本销毁时才真正释放底层资源。
 */
class Base_Link
{
public:
    Base_Link() = default;
    /*
     *@brief 用一条已建立的会话构造(主要由 Server::get_link 使用)
     */
    explicit Base_Link(std::shared_ptr<detail::Session> session);
    ~Base_Link();

    Base_Link(const Base_Link &) = default;
    Base_Link(Base_Link &&) noexcept = default;
    Base_Link &operator=(const Base_Link &) = default;
    Base_Link &operator=(Base_Link &&) noexcept = default;

    /*
     *@brief 检查连接是否有效
     */
    bool valid() const noexcept;
    /*
     *@brief 关闭连接(线程安全,立即生效)
     */
    void Close(); // 最高优先级：立即生效

    /*
     *@brief 获取连接的IP地址
     */
    std::string get_ip() const;
    /*
     *@brief 获取对端地址(IP:端口)，用于日志中区分同一 IP 的不同连接
     *@return "127.0.0.1:53211" 形式的字符串;连接无效时返回空串
     */
    std::string get_peer() const;
    /*
     *@brief 本连接是否为 TLS 加密连接
     */
    bool is_tls() const noexcept;
    /*
     *@brief 本连接协商出的 TLS 协议版本(如 "TLS 1.3")
     *@return 非 TLS 连接返回空串
     */
    std::string tls_protocol() const;
    /*
     *@brief 把本明文连接升级为 TLS 加密连接(服务端握手)
     *@param ctx 由 TLS::make_server_context 创建的服务端上下文
     *@param handshake_timeout_ms 握手总超时(毫秒),0 表示不限制
     *@param error 可选:失败时写入可读原因
     *@return true 表示握手成功,连接已可正常收发(自动加解密)
     *@warning 必须在任何收发之前调用;已在 TLS 连接上调用会被忽略(返回 true)
     */
    bool start_tls(std::shared_ptr<TLS::Context> ctx, int handshake_timeout_ms,
                   std::string *error);

    // -------- 发送（与接收互不阻塞） --------
    /*
     *@brief 发送string数据
     *@param msg 要发送的string数据
     */
    void Send_str(const std::string &msg);
    /*
     *@brief 发送字节数据
     *@param msg 要发送的字节数据
     */
    void Send_sb(const std::vector<char> &msg);

    // -------- 接收（与发送互不阻塞） --------
    /*
     *@brief 接收字符串数据
     *@param size 接收数据的大小
     *@param timeout_ms 等待超时（毫秒），0 表示无限等待；超时返回已收到的数据（可能为空）
     */
    std::string Receive_str(size_t size = 1024, int timeout_ms = 0);
    /*
     *@brief 接收字节数据
     *@param size 接收数据的大小
     *@param timeout_ms 等待超时（毫秒），0 表示无限等待；超时返回已收到的数据（可能为空）
     */
    std::vector<char> Receive_sb(size_t size = 1024, int timeout_ms = 0);
    /*
     *@brief 接收字符串数据直到遇到指定的结束标志
     *@param end 结束标志字符串
     *@param timeout_ms 等待超时（毫秒），0 表示无限等待；超时返回已收到的数据（可能为空）
     */
    std::string Receive_str_until(const std::string &end, int timeout_ms = 0);
    /*
     *@brief 接收字节数据直到遇到指定的结束标志
     *@param end 结束标志字符串
     *@param timeout_ms 等待超时（毫秒），0 表示无限等待；超时返回已收到的数据（可能为空）
     */
    std::vector<char> Receive_sb_until(const std::string &end, int timeout_ms = 0);
    /*
     *@brief 检测是否存在待读取的信息（不含阻塞）
     *@return true  表示有数据可读（可立即调用 Receive_* 且不会阻塞）
     *        false 表示当前无数据或连接已失效
     *@note  非阻塞探测，不会消费数据
     */
    bool has_data();

    /*
     *@brief 读取直到遇到结束标志 end(不含 end 本身),并限制累积长度
     *@param end 结束标志字符串
     *@param timeout_ms 等待超时(毫秒),0 表示无限等待
     *@param max_bytes 允许累积的最大字节数(不含 end),0 表示不限制
     *@param out 输出:end 之前的数据(仅在返回 Ok 时有效)
     *@return 读取状态(见 ReadStatus)
     *@note  已读入但未消费的多余字节保留在连接内部缓存中,不会被丢弃;
     *       返回非 Ok 时连接可能已失效,应检查 valid()
     */
    ReadStatus Read_until(const std::string &end, int timeout_ms,
                          size_t max_bytes, std::string &out);

    /*
     *@brief 半关闭写方向:向对端发送 FIN(TLS 连接先发 close_notify),但仍可读取
     *@note  用于"发完响应后优雅关闭",保证响应能被对端收完
     */
    void Shutdown_send();

    /*
     *@brief 丢弃对端剩余输入数据,直到超时/达到上限/对端关闭
     *@param timeout_ms 最长等待(毫秒),0 表示不等待
     *@param max_bytes 最多丢弃的字节数,防止被大量数据拖住
     *@note  发送错误响应后调用,可避免未读数据触发 RST 冲掉已发出的响应
     */
    void Drain(int timeout_ms, size_t max_bytes = 256 * 1024);

private:
    struct SharedState; // 定义在 .cpp 中
    std::shared_ptr<SharedState> state_;

    void Send_raw(const char *data, size_t len);
};

/*
 *@class Server
 *@brief TCP服务器类，提供监听和接受连接的功能
 */
class Server
{
public:
    Server() = default;
    /*
     *@brief 在指定端口上开始监听
     *@param port          监听端口
     *@param bind_address  绑定地址,默认 "0.0.0.0"(所有 IPv4 网卡),
     *                     也可以传 "127.0.0.1" 或 IPv6 地址
     *@note  构造后用 valid() 判断是否监听成功
     */
    explicit Server(unsigned short port, const std::string &bind_address = "0.0.0.0");
    ~Server();

    Server(const Server &) = delete;
    Server(Server &&) = delete;
    Server &operator=(const Server &) = delete;
    Server &operator=(Server &&) = delete;

    /*
     *@brief 构建一个新的TCP连接
     *       阻塞直到有新连接到来，或服务器被 Close() 关闭
     *@return 返回一个Base_Link对象，表示新的TCP连接;
     *        服务器已关闭或发生不可恢复错误时返回无效对象(valid() == false)
     *@note  accept 的瞬时失败会在内部短暂退避后重试,不会因此结束接受循环
     */
    Base_Link get_link();

    /*
     *@brief 服务器是否处于监听状态
     */
    bool valid() const noexcept;

    /*
     *@brief 关闭服务器监听
     *@note  线程安全:可从其它线程调用,会立即唤醒阻塞在 get_link() 中的线程
     */
    void Close();

private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
};

} // namespace TCP
#endif // TCP_H
