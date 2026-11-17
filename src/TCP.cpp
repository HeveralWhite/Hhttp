#include "TCP.h"
#include "Log.h"
#include "TLS.h"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <utility>

namespace asio = boost::asio;
namespace ssl = boost::asio::ssl;
using asio::ip::tcp;
using boost::system::error_code;

namespace TCP
{
namespace
{
/*
 *@brief 单次 send 的阻塞上限(毫秒)
 *@note  对端长时间不读(接收窗口为 0)时,写操作会一直挂着;30 秒没有进展就
 *       认为这条连接已经失联,由上层关闭它。只要对端还在收,每次写都能在很
 *       短时间内完成,大文件下载不受影响。
 */
constexpr int kSendTimeoutMs = 30000;

/*
 *@brief Session 接收接口的额外返回码
 *@note  正数 = 读到的字节数;0 = 对端正常关闭;-1 = 连接出错;-2 = 等待超时
 */
constexpr int kRecv_error = -1;
constexpr int kRecv_timeout = -2;

/*
 *@brief 接收队列高水位
 *@note  Session 的读循环是"推送"模型:数据到得比上层取得快时,先攒在接收
 *       队列里。攒到这个上限就暂停读,让 TCP 窗口把对端压住(背压),
 *       避免一个不消费数据的连接把整个进程内存吃光。
 */
constexpr std::size_t kRxHighWater = 256 * 1024;

/*
 *@brief 发送队列高水位
 *@note  Send 只负责把数据排进发送队列,真正的写由 I/O 线程按顺序完成。
 *       队列涨到这个上限时调用方会阻塞等待(背压),因此"对端不读"仍然会
 *       在 kSendTimeoutMs 之后失败,而不是把内存吃光。
 */
constexpr std::size_t kTxHighWater = 256 * 1024;

/*
 *@brief 进程级 I/O 线程池
 *@note  所有 socket 的异步读写、TLS 握手都跑在这里。用 new 构造且不析构:
 *       进程退出时不需要和静态对象的析构顺序较劲(线程正在 io_context 里等
 *       事件,直接随进程结束最安全)。
 */
class Io_runtime
{
public:
    static Io_runtime &instance()
    {
        static Io_runtime *runtime = new Io_runtime();
        return *runtime;
    }

    asio::io_context &context() noexcept
    {
        return io_;
    }

private:
    Io_runtime() : work_(asio::make_work_guard(io_))
    {
        unsigned count = std::thread::hardware_concurrency();
        if (count < 2)
            count = 2;
        if (count > 8)
            count = 8; // I/O 线程不需要跟 CPU 核数一样多

        for (unsigned i = 0; i < count; ++i)
        {
            std::thread([this]
            {
                for (;;)
                {
                    try
                    {
                        io_.run();
                        break; // run() 正常返回(work guard 被释放):结束线程
                    }
                    catch (...)
                    {
                        // 单个 handler 抛异常不应该让整个 I/O 线程消失
                    }
                }
            }).detach();
        }
    }

    asio::io_context io_;
    asio::executor_work_guard<asio::io_context::executor_type> work_;
};

/*
 *@brief 一次同步等待的共享状态(用于把异步完成转换成阻塞返回)
 */
struct Sync_wait
{
    std::mutex mtx;
    std::condition_variable cv;
    bool done = false;
    bool ok = false;
    int code = -1;
    std::string error;
};

/*
 *@brief 把剩余时间换算成毫秒(<=0 表示已到点)
 */
int Millis_left(std::chrono::steady_clock::time_point deadline)
{
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline)
        return 0;
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        deadline - now)
                    .count();
    return ms > 0 ? static_cast<int>(ms) : 0;
}

/*
 *@brief 把 OpenSSL 的版本名规范成 "TLS 1.3" 这种形式
 */
std::string Normalize_tls_version(const char *version)
{
    if (version == nullptr)
        return "TLS";
    std::string text(version);
    // OpenSSL: "TLSv1.3" / "TLSv1.2" / "TLSv1.1" / "TLSv1"
    const std::string prefix = "TLSv";
    if (text.compare(0, prefix.size(), prefix) == 0)
        return "TLS " + text.substr(prefix.size());
    return text;
}
} // namespace

// ==================== Session ====================

/*
 *@class Session
 *@brief 一条连接的真实 I/O 会话:所有 socket 操作都跑在 io_context 的
 *       strand 上,对外提供"阻塞取数据 / 阻塞发数据"的同步接口。
 *
 *@note  线程安全:
 *         - 收发 API(receive/send/has_data/close/valid)可从任意线程调用;
 *         - 所有 socket 操作都 post 到 strand_,不会出现两个线程同时碰同一个
 *           Asio 对象(Asio 要求共享对象不能并发访问);
 *         - rx_ 队列、eof 标志由 mutex_ 保护,cv_ 负责唤醒等待者。
 */
namespace detail
{
class Session : public std::enable_shared_from_this<Session>
{
public:
    Session(tcp::socket socket, unsigned id)
        : io_(Io_runtime::instance().context())
        , strand_(asio::make_strand(io_))
        , socket_(std::move(socket))
        , id_(id)
    {
        error_code ec;
        const auto endpoint = socket_.remote_endpoint(ec);
        if (!ec)
        {
            peer_ip_ = endpoint.address().to_string();
            peer_port_ = endpoint.port();
        }
    }

    ~Session()
    {
        // 兜底:正常路径由 close() 关闭;这里只保证句柄不泄漏
        error_code ec;
        if (tls_stream_)
            tls_stream_->next_layer().close(ec);
        else
            socket_.close(ec);
    }

    Session(const Session &) = delete;
    Session &operator=(const Session &) = delete;

    // -------- 基本状态 --------

    bool valid() const noexcept
    {
        return !closed_.load(std::memory_order_acquire);
    }

    bool is_tls() const noexcept
    {
        return tls_.load(std::memory_order_acquire);
    }

    std::string peer_ip() const
    {
        return peer_ip_;
    }

    std::string peer() const
    {
        if (peer_ip_.empty())
            return std::string();
        return peer_ip_ + ":" + std::to_string(peer_port_);
    }

    std::string tls_protocol() const
    {
        std::lock_guard<std::mutex> lk(mutex_);
        return tls_version_;
    }

    // -------- 接收 --------

    /*
     *@brief 阻塞取最多 max 字节
     *@param timeout_ms <=0 表示无限等待
     *@return >0 字节数;0 对端正常关闭;-1 出错;-2 超时
     */
    int receive(char *dst, std::size_t max, int timeout_ms)
    {
        if (max == 0)
            return 0;
        ensure_started();

        std::unique_lock<std::mutex> lk(mutex_);
        auto available = [this] { return rx_.size() - rx_offset_; };

        if (timeout_ms <= 0)
        {
            cv_.wait(lk, [&] { return available() > 0 || eof_; });
        }
        else if (!cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                               [&] { return available() > 0 || eof_; }))
        {
            return kRecv_timeout;
        }

        if (available() > 0)
        {
            const std::size_t count = std::min(max, available());
            std::memcpy(dst, rx_.data() + rx_offset_, count);
            rx_offset_ += count;
            if (rx_offset_ >= rx_.size())
            {
                rx_.clear();
                rx_offset_ = 0;
            }
            const bool resume = paused_.exchange(false);
            lk.unlock();
            if (resume)
                start_read(); // 队列降下来了,继续从对端收(背压解除)
            return static_cast<int>(count);
        }

        return eof_is_error_ ? kRecv_error : 0;
    }

    /*
     *@brief 非阻塞探测:队列里是否已有数据
     */
    bool has_data()
    {
        std::lock_guard<std::mutex> lk(mutex_);
        return rx_.size() > rx_offset_;
    }

    // -------- 发送 --------

    /*
     *@brief 把数据排进发送队列(真正写出由 I/O 线程按顺序完成)
     *@param timeout_ms 背压等待上限:队列已满时最多等这么久,0 表示用默认值
     *@return false 表示连接已不可用 / 背压等待超时
     *@note  不在这里同步等待写完:每次 Send 都跨线程等一次会把小响应的
     *       吞吐打掉一半。需要"数据确实已经交给内核"时调用 flush()。
     */
    bool send(const char *data, std::size_t len, int timeout_ms)
    {
        if (closed_.load(std::memory_order_acquire))
            return false;
        if (len == 0)
            return true;

        {
            std::unique_lock<std::mutex> lk(tx_mtx_);
            if (tx_bytes_ >= kTxHighWater)
            {
                const int wait_ms = timeout_ms > 0 ? timeout_ms : kSendTimeoutMs;
                if (!tx_cv_.wait_for(lk, std::chrono::milliseconds(wait_ms), [this]
                {
                    return tx_bytes_ < kTxHighWater || closed_.load() || write_failed_;
                }))
                {
                    return false; // 对端长时间不收:按失联处理
                }
            }
            if (closed_.load(std::memory_order_acquire) || write_failed_)
                return false;

            tx_.emplace_back(data, len);
            tx_bytes_ += len;

            if (writing_)
                return true; // 已经有写操作在跑,按队列顺序追加即可
            writing_ = true;
        }

        auto self = shared_from_this();
        asio::post(strand_, [self] { self->do_write(); });
        return true;
    }

    /*
     *@brief 等待发送队列清空(数据已全部交给内核)
     *@return false 表示等待超时或写失败
     */
    bool flush(int timeout_ms)
    {
        std::unique_lock<std::mutex> lk(tx_mtx_);
        const int wait_ms = timeout_ms > 0 ? timeout_ms : kSendTimeoutMs;
        tx_cv_.wait_for(lk, std::chrono::milliseconds(wait_ms), [this]
        {
            return (tx_bytes_ == 0 && !writing_) || closed_.load() || write_failed_;
        });
        return tx_bytes_ == 0 && !write_failed_ && !closed_.load();
    }

    /*
     *@brief 半关闭写方向(发送 FIN;TLS 连接先发 close_notify)
     */
    void shutdown_send()
    {
        if (closed_.load(std::memory_order_acquire))
            return;

        // 先把排队的响应真正写出去,再发 FIN / close_notify
        flush(kSendTimeoutMs);

        auto self = shared_from_this();
        asio::post(strand_, [self]
        {
            error_code ec;
            if (self->tls_stream_)
            {
                // 只发 close_notify:不等待对端的 close_notify,避免在这里挂住
                //
                // 注意必须捕获 self:SSL_shutdown 是异步的(实际 IO 可能要到下一次
                // 事件循环才完成),若不延长 Session 生命周期,连接对象可能在
                // shutdown 完成前被释放,回调里再访问已 free 的 SSL 对象就是
                // 0xC0000005(访问违例)。
                self->tls_stream_->async_shutdown(
                    asio::bind_executor(self->strand_,
                                        [self](const error_code &) {}));
            }
            else
            {
                self->socket_.shutdown(tcp::socket::shutdown_send, ec);
            }
        });
    }

    /*
     *@brief 关闭连接(线程安全,立即唤醒所有等待者)
     */
    void close()
    {
        if (!closed_.exchange(true, std::memory_order_acq_rel))
        {
            {
                std::lock_guard<std::mutex> lk(mutex_);
                eof_ = true;
                eof_is_error_ = false;
            }
            cv_.notify_all();
            tx_cv_.notify_all();

            auto self = shared_from_this();
            asio::post(strand_, [self]
            {
                // 已经没有任何待写数据:直接关
                {
                    std::lock_guard<std::mutex> lk(self->tx_mtx_);
                    if (self->tx_bytes_ == 0 && !self->writing_)
                    {
                        self->do_close();
                        return;
                    }
                }
                /*
                 * 还有排队/在途的响应:等写队列排空后再关,最多等 500ms。
                 * 否则"响应刚入队就 Close"会把还没写出去的数据丢掉
                 * (对端看到的是连接直接断开)。
                 */
                auto timer = std::make_shared<asio::steady_timer>(self->strand_);
                self->close_timer_ = timer;
                timer->expires_after(std::chrono::milliseconds(500));
                timer->async_wait(asio::bind_executor(
                                      self->strand_,
                                      [self, timer](const error_code &ec)
                {
                    if (!ec)
                        self->do_close();
                }));
            });
        }
        else
        {
            cv_.notify_all();
            tx_cv_.notify_all();
        }
    }

    // -------- TLS 握手 --------

    /*
     *@brief 在连接上完成 TLS 服务端握手
     *@return 0 成功;-1 失败
     *@note  必须在开始读之前调用(上层拿到连接后第一件事就是它)
     */
    int start_tls(const std::shared_ptr<TLS::Context> &ctx, int handshake_timeout_ms,
                  std::string *error)
    {
        if (!ctx)
        {
            if (error)
                *error = "empty TLS context";
            return -1;
        }
        if (is_tls())
            return 0;
        if (started_.load(std::memory_order_acquire))
        {
            if (error)
                *error = "TLS upgrade must happen before any read/write";
            return -1;
        }
        if (closed_.load(std::memory_order_acquire))
        {
            if (error)
                *error = "connection is closed";
            return -1;
        }

        auto op = std::make_shared<Sync_wait>();
        auto self = shared_from_this();

        asio::post(strand_, [self, ctx, op, handshake_timeout_ms]
        {
            error_code ec;
            try
            {
                self->tls_ctx_ = ctx;
                self->tls_stream_ = std::make_unique<ssl::stream<tcp::socket>>(
                                        std::move(self->socket_), ctx->native());
            }
            catch (const std::exception &e)
            {
                std::lock_guard<std::mutex> lk(op->mtx);
                op->done = true;
                op->ok = false;
                op->error = std::string("cannot create TLS stream: ") + e.what();
                op->cv.notify_all();
                return;
            }

            auto &stream = *self->tls_stream_;

            /*
             * 握手超时定时器。注意必须在握手结束时 cancel():
             * 否则定时器会一直挂到超时才触发,而它的 handler 捕获了 self,
             * 相当于握手成功后还把这个连接(及其 socket / SSL 对象)多留
             * 十几秒 —— 高并发下就是内存和句柄持续上涨。
             */
            std::shared_ptr<asio::steady_timer> timer;
            if (handshake_timeout_ms > 0)
            {
                timer = std::make_shared<asio::steady_timer>(self->strand_);
                timer->expires_after(std::chrono::milliseconds(handshake_timeout_ms));
            }

            // 握手完成(或失败)时记录协议版本并唤醒等待者
            auto on_handshake = asio::bind_executor(
                                    self->strand_,
                                    [self, op, timer](const error_code &handshake_ec)
            {
                if (timer)
                    timer->cancel(); // 握手已结束,超时定时器不再需要

                std::lock_guard<std::mutex> lk(op->mtx);
                if (op->done)
                    return; // 已经被超时定时器处理
                op->done = true;
                op->ok = !handshake_ec;
                op->error = handshake_ec ? handshake_ec.message() : std::string();
                if (!handshake_ec)
                {
                    self->tls_.store(true, std::memory_order_release);
                    const char *version = SSL_get_version(self->tls_stream_->native_handle());
                    std::lock_guard<std::mutex> vl(self->mutex_);
                    self->tls_version_ = Normalize_tls_version(version);
                }
                op->cv.notify_all();
            });

            stream.async_handshake(ssl::stream_base::server, on_handshake);

            if (timer)
            {
                // 握手的总超时:到点后取消握手,避免半条 ClientHello 把连接挂死
                timer->async_wait(asio::bind_executor(
                                      self->strand_,
                                      [self, op, timer](const error_code &timer_ec)
                {
                    if (timer_ec)
                        return; // 定时器被取消 = 握手已经结束了
                    bool expired = false;
                    {
                        std::lock_guard<std::mutex> lk(op->mtx);
                        if (!op->done)
                        {
                            op->done = true;
                            op->ok = false;
                            op->error = "TLS handshake timed out";
                            expired = true;
                        }
                    }
                    if (expired)
                    {
                        op->cv.notify_all();
                        error_code ec;
                        if (self->tls_stream_)
                            self->tls_stream_->next_layer().cancel(ec);
                    }
                }));
            }
        });

        const int wait_ms = handshake_timeout_ms > 0 ? handshake_timeout_ms + 2000 : 0;
        std::unique_lock<std::mutex> lk(op->mtx);
        if (wait_ms > 0)
        {
            if (!op->cv.wait_for(lk, std::chrono::milliseconds(wait_ms),
                                 [&] { return op->done; }))
            {
                lk.unlock();
                close();
                if (error)
                    *error = "TLS handshake timed out";
                return -1;
            }
        }
        else
        {
            op->cv.wait(lk, [&] { return op->done; });
        }

        const bool ok = op->ok;
        if (error)
            *error = op->error;
        if (!ok)
            close();
        return ok ? 0 : -1;
    }

private:
    /*
     *@brief 首次收发前启动读循环(懒启动)
     *@note  TLS 握手要求"升级前不能有读操作",所以读循环不能在建链时就开始;
     *       由第一次 receive/has_data/send 触发即可(握手期间的读写不会经过
     *       这些接口)。
     */
    void ensure_started()
    {
        if (closed_.load(std::memory_order_acquire))
            return;
        if (started_.exchange(true, std::memory_order_acq_rel))
            return;
        start_read();
    }

    void start_read()
    {
        if (closed_.load(std::memory_order_acquire))
            return;
        if (reading_.exchange(true, std::memory_order_acq_rel))
            return;

        auto self = shared_from_this();
        asio::post(strand_, [self] { self->do_read(); });
    }

    void do_read()
    {
        if (closed_.load(std::memory_order_acquire))
        {
            reading_.store(false, std::memory_order_release);
            return;
        }

        auto self = shared_from_this();
        auto handler = asio::bind_executor(
                           strand_,
                           [self](const error_code &ec, std::size_t n)
        {
            self->reading_.store(false, std::memory_order_release);
            self->on_read(ec, n);
        });

        if (tls_stream_)
            tls_stream_->async_read_some(asio::buffer(read_buffer_, sizeof(read_buffer_)),
                                         handler);
        else
            socket_.async_read_some(asio::buffer(read_buffer_, sizeof(read_buffer_)),
                                    handler);
    }

    void on_read(const error_code &ec, std::size_t count)
    {
        if (ec)
        {
            {
                std::lock_guard<std::mutex> lk(mutex_);
                eof_ = true;
                eof_is_error_ = (ec != asio::error::eof);
            }
            cv_.notify_all();
            return;
        }

        bool resume = true;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (rx_offset_ > 0 && rx_offset_ >= rx_.size())
            {
                rx_.clear();
                rx_offset_ = 0;
            }
            rx_.append(read_buffer_, count);

            // 队列超过高水位:暂停读,等上层把数据取走(背压)
            if (rx_.size() - rx_offset_ >= kRxHighWater)
            {
                paused_.store(true, std::memory_order_release);
                resume = false;
            }
        }
        cv_.notify_all();

        if (resume)
            start_read();
    }

    /*
     *@brief 按队列顺序写下一段数据
     *@note  所有写操作都在 strand 上串行执行,因此队列天然有序;
     *       写失败时把连接标记为失效并唤醒所有等待者。
     */
    void do_write()
    {
        std::shared_ptr<std::string> chunk;
        {
            std::lock_guard<std::mutex> lk(tx_mtx_);
            if (write_failed_ || tx_.empty())
            {
                const bool should_close = closed_.load(std::memory_order_acquire);
                writing_ = false;
                tx_cv_.notify_all();
                if (should_close)
                    do_close(); // 队列已排空且已请求关闭:立刻收尾
                return;
            }
            // 注意:closed_ 为真时仍要把"关闭前已排队的数据"写完
            // (例如响应刚入队、上层紧接着 Close);只拒绝之后新进的数据。
            chunk = std::make_shared<std::string>(std::move(tx_.front()));
            tx_.pop_front();
        }

        auto self = shared_from_this();
        auto handler = asio::bind_executor(
                           strand_,
                           [self, chunk](const error_code &ec, std::size_t)
        {
            if (ec)
            {
                {
                    std::lock_guard<std::mutex> lk(self->tx_mtx_);
                    self->write_failed_ = true;
                    self->tx_.clear();
                    self->tx_bytes_ = 0;
                    self->writing_ = false;
                }
                self->tx_cv_.notify_all();
                self->close();
                return;
            }

            {
                std::lock_guard<std::mutex> lk(self->tx_mtx_);
                self->tx_bytes_ -= std::min(self->tx_bytes_, chunk->size());
                self->tx_cv_.notify_all(); // 唤醒被背压挡住的 send
            }
            self->do_write();
        });

        if (tls_stream_)
            asio::async_write(*tls_stream_, asio::buffer(*chunk), handler);
        else
            asio::async_write(socket_, asio::buffer(*chunk), handler);
    }

    void do_close()
    {
        if (close_done_.exchange(true, std::memory_order_acq_rel))
            return;

        // 关闭已经发生:把"等排空"的定时器取消掉,免得它再白占 500ms
        // (定时器 handler 捕获了 self,会拖住 Session 的释放)
        if (close_timer_)
        {
            close_timer_->cancel();
            close_timer_.reset();
        }

        error_code ec;
        if (tls_stream_)
        {
            tls_stream_->next_layer().cancel(ec);
            tls_stream_->next_layer().close(ec);
        }
        else
        {
            socket_.cancel(ec);
            socket_.close(ec);
        }
        reading_.store(false, std::memory_order_release);
    }

    asio::io_context &io_;
    asio::strand<asio::io_context::executor_type> strand_;
    tcp::socket socket_;
    std::unique_ptr<ssl::stream<tcp::socket>> tls_stream_;
    std::shared_ptr<TLS::Context> tls_ctx_; ///< 持有上下文,保证 SSL_CTX 生命周期

    unsigned id_ = 0;
    std::string peer_ip_;
    std::uint16_t peer_port_ = 0;

    std::atomic<bool> tls_{false};
    std::atomic<bool> started_{false};
    std::atomic<bool> closed_{false};
    std::atomic<bool> reading_{false};
    std::atomic<bool> paused_{false};
    std::atomic<bool> close_done_{false};
    std::shared_ptr<asio::steady_timer> close_timer_; ///< 仅 strand 上访问

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::string rx_;             ///< 已收到的明文(可能消费到一半)
    std::size_t rx_offset_ = 0;  ///< 已消费的前缀长度
    bool eof_ = false;
    bool eof_is_error_ = false;
    std::string tls_version_;

    // 发送队列(按顺序写;tx_bytes_ 统计"排队中 + 正在写"的字节数)
    std::mutex tx_mtx_;
    std::condition_variable tx_cv_;
    std::deque<std::string> tx_;
    std::size_t tx_bytes_ = 0;
    bool writing_ = false;
    bool write_failed_ = false;

    char read_buffer_[16 * 1024] = {};
};
} // namespace detail

// ==================== Base_Link::SharedState ====================
// 所有同源 Base_Link 副本共享此结构。
//
// 锁层级：
//   s_mtx : 串行化 send，不影响 recv，也不影响 Close。
//   r_mtx : 串行化 recv 并保护 cache，不影响 send，也不影响 Close。
// Close() 只做"置标志 + 取消会话",不参与这两把锁的竞争 → 关闭优先级最高。
struct Base_Link::SharedState
{
    std::shared_ptr<detail::Session> session;
    std::vector<char> cache; // 由 r_mtx 保护
    std::atomic<bool> is_link{false};

    mutable std::mutex h_mtx; // 保留给"取句柄"语义(目前仅用于判空)
    mutable std::mutex s_mtx;
    mutable std::mutex r_mtx;

    /*
     *@brief 逻辑关闭:立即标记失效并取消底层 I/O,唤醒所有等待者
     */
    void Close()
    {
        is_link.store(false, std::memory_order_release);
        if (session)
            session->close();
    }

    void MarkDead() noexcept
    {
        is_link.store(false, std::memory_order_release);
    }

    /*
     *@brief 从连接读取数据(自动区分明文 socket 与 TLS 解密)
     *@return >0 读到的字节数;0 对端已关闭;-1 出错;-2 等待超时
     *@note  调用者需已持有 r_mtx
     */
    int Recv(char *buffer, size_t size, int timeout_ms)
    {
        if (!session)
            return -1;
        return session->receive(buffer, size, timeout_ms);
    }

    /*
     *@brief 是否有数据可读
     *@note  调用者需已持有 r_mtx
     */
    bool Has_data()
    {
        return session && session->has_data();
    }
};

// ==================== 构造 / 析构 / 状态 ====================

Base_Link::Base_Link(std::shared_ptr<detail::Session> session)
{
    if (!session)
    {
        Log::error("Link failed: empty session");
        return;
    }
    state_ = std::make_shared<SharedState>();
    state_->session = std::move(session);
    state_->is_link.store(true, std::memory_order_release);
}

// 显式定义在 .cpp，使 shared_ptr<SharedState> 的析构能访问完整类型
Base_Link::~Base_Link() = default;

bool Base_Link::valid() const noexcept
{
    return state_ && state_->is_link.load(std::memory_order_acquire);
}

void Base_Link::Close()
{
    if (state_)
        state_->Close();
}

std::string Base_Link::get_ip() const
{
    return state_ && state_->session ? state_->session->peer_ip() : std::string();
}

std::string Base_Link::get_peer() const
{
    return state_ && state_->session ? state_->session->peer() : std::string();
}

bool Base_Link::is_tls() const noexcept
{
    return state_ && state_->session && state_->session->is_tls();
}

std::string Base_Link::tls_protocol() const
{
    return state_ && state_->session ? state_->session->tls_protocol() : std::string();
}

bool Base_Link::start_tls(std::shared_ptr<TLS::Context> ctx, int handshake_timeout_ms,
                          std::string *error)
{
    if (!state_ || !state_->session)
    {
        if (error)
            *error = "connection is not available";
        return false;
    }
    const int result = state_->session->start_tls(ctx, handshake_timeout_ms, error);
    if (result != 0)
        state_->MarkDead();
    return result == 0;
}

// ==================== 发送 ====================

void Base_Link::Send_raw(const char *data, size_t len)
{
    if (!valid() || len == 0)
        return;

    std::lock_guard<std::mutex> lk(state_->s_mtx); // 仅锁发送
    if (!state_->is_link.load(std::memory_order_acquire))
        return;

    if (!state_->session->send(data, len, kSendTimeoutMs))
        state_->MarkDead();
}

void Base_Link::Send_str(const std::string &msg)
{
    Send_raw(msg.data(), msg.size());
}

void Base_Link::Send_sb(const std::vector<char> &msg)
{
    Send_raw(msg.data(), msg.size());
}

// ==================== 接收 ====================

std::string Base_Link::Receive_str(size_t size, int timeout_ms)
{
    if (!valid() || size == 0)
        return "";
    std::lock_guard<std::mutex> lk(state_->r_mtx);
    if (!state_->is_link.load(std::memory_order_acquire))
        return "";

    // 优先从缓存读取（缓存有数据时无需等待）
    if (!state_->cache.empty())
    {
        size_t n = std::min(size, state_->cache.size());
        std::string result(state_->cache.begin(), state_->cache.begin() + n);
        state_->cache.erase(state_->cache.begin(), state_->cache.begin() + n);
        return result;
    }

    std::vector<char> buffer(size);
    int ret = state_->Recv(buffer.data(), buffer.size(), timeout_ms);
    if (ret > 0)
        return std::string(buffer.data(), static_cast<size_t>(ret));
    if (ret == kRecv_timeout)
        return ""; // 等待超时:连接仍然有效

    state_->MarkDead();
    return "";
}

std::vector<char> Base_Link::Receive_sb(size_t size, int timeout_ms)
{
    if (!valid() || size == 0)
        return {};
    std::lock_guard<std::mutex> lk(state_->r_mtx);
    if (!state_->is_link.load(std::memory_order_acquire))
        return {};

    if (!state_->cache.empty())
    {
        size_t n = std::min(size, state_->cache.size());
        std::vector<char> result(state_->cache.begin(), state_->cache.begin() + n);
        state_->cache.erase(state_->cache.begin(), state_->cache.begin() + n);
        return result;
    }

    std::vector<char> buffer(size);
    int ret = state_->Recv(buffer.data(), buffer.size(), timeout_ms);
    if (ret > 0)
        return std::vector<char>(buffer.begin(), buffer.begin() + ret);
    if (ret == kRecv_timeout)
        return {}; // 等待超时:连接仍然有效

    state_->MarkDead();
    return {};
}

std::string Base_Link::Receive_str_until(const std::string &end, int timeout_ms)
{
    if (!valid() || end.empty())
        return "";
    std::lock_guard<std::mutex> lk(state_->r_mtx);
    if (!state_->is_link.load(std::memory_order_acquire))
        return "";

    // 结束标志可能跨两次读:只需从"上次读到的位置 - (end.size()-1)"开始找,
    // 不必每次重扫整个缓存(否则大段无结束标志的数据会退化成 O(n^2))
    const std::size_t overlap = end.size() - 1;
    auto find_end = [&](std::size_t from)
    {
        if (from > state_->cache.size())
            from = state_->cache.size();
        return std::search(state_->cache.begin() + static_cast<std::ptrdiff_t>(from),
                           state_->cache.end(), end.begin(), end.end());
    };

    // 缓存中已存在结束标记
    auto it = find_end(0);
    if (it != state_->cache.end())
    {
        std::string result(state_->cache.begin(), it);
        state_->cache.erase(state_->cache.begin(),
                            it + static_cast<std::ptrdiff_t>(end.size()));
        return result;
    }

    const bool infinite = (timeout_ms <= 0);
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(infinite ? 0 : timeout_ms);

    while (true)
    {
        int wait_ms = 0;
        if (!infinite)
        {
            wait_ms = Millis_left(deadline);
            if (wait_ms <= 0)
                break; // 总等待时间耗尽
        }

        char buffer[1024];
        const std::size_t old_size = state_->cache.size();
        int ret = state_->Recv(buffer, sizeof(buffer), wait_ms);
        if (ret > 0)
        {
            state_->cache.insert(state_->cache.end(), buffer, buffer + ret);
            it = find_end(old_size >= overlap ? old_size - overlap : 0);
            if (it != state_->cache.end())
            {
                std::string result(state_->cache.begin(), it);
                state_->cache.erase(state_->cache.begin(),
                                    it + static_cast<std::ptrdiff_t>(end.size()));
                return result;
            }
        }
        else if (ret == kRecv_timeout)
        {
            break; // 等待超时:连接仍然有效,把已缓存的数据返回
        }
        else
        {
            state_->MarkDead();
            break;
        }
    }

    // 连接关闭 / 超时：把已经缓存到的残留数据返回
    if (!state_->cache.empty())
    {
        std::string result(state_->cache.begin(), state_->cache.end());
        state_->cache.clear();
        return result;
    }
    return "";
}

std::vector<char> Base_Link::Receive_sb_until(const std::string &end, int timeout_ms)
{
    if (!valid() || end.empty())
        return {};
    std::lock_guard<std::mutex> lk(state_->r_mtx);
    if (!state_->is_link.load(std::memory_order_acquire))
        return {};

    const std::size_t overlap = end.size() - 1;
    auto find_end = [&](std::size_t from)
    {
        if (from > state_->cache.size())
            from = state_->cache.size();
        return std::search(state_->cache.begin() + static_cast<std::ptrdiff_t>(from),
                           state_->cache.end(), end.begin(), end.end());
    };

    auto it = find_end(0);
    if (it != state_->cache.end())
    {
        std::vector<char> result(state_->cache.begin(), it);
        state_->cache.erase(state_->cache.begin(),
                            it + static_cast<std::ptrdiff_t>(end.size()));
        return result;
    }

    const bool infinite = (timeout_ms <= 0);
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(infinite ? 0 : timeout_ms);

    while (true)
    {
        int wait_ms = 0;
        if (!infinite)
        {
            wait_ms = Millis_left(deadline);
            if (wait_ms <= 0)
                break;
        }

        char buffer[1024];
        const std::size_t old_size = state_->cache.size();
        int ret = state_->Recv(buffer, sizeof(buffer), wait_ms);
        if (ret > 0)
        {
            state_->cache.insert(state_->cache.end(), buffer, buffer + ret);
            it = find_end(old_size >= overlap ? old_size - overlap : 0);
            if (it != state_->cache.end())
            {
                std::vector<char> result(state_->cache.begin(), it);
                state_->cache.erase(state_->cache.begin(),
                                    it + static_cast<std::ptrdiff_t>(end.size()));
                return result;
            }
        }
        else if (ret == kRecv_timeout)
        {
            break;
        }
        else
        {
            state_->MarkDead();
            break;
        }
    }

    if (!state_->cache.empty())
    {
        std::vector<char> result(state_->cache.begin(), state_->cache.end());
        state_->cache.clear();
        return result;
    }
    return {};
}

// ==================== 可用性探测 ====================

bool Base_Link::has_data()
{
    if (!valid())
        return false;

    // 与接收共用 r_mtx：避免与正在执行的 Receive 交错访问 cache
    std::lock_guard<std::mutex> lk(state_->r_mtx);
    if (!state_->is_link.load(std::memory_order_acquire))
        return false;

    // 1) 先看内部缓存（之前 Receive_until 等可能残留的数据）
    if (!state_->cache.empty())
        return true;

    // 2) 再看会话接收队列
    return state_->Has_data();
}

// ==================== 有界读取 ====================

ReadStatus Base_Link::Read_until(const std::string &end, int timeout_ms,
                                 size_t max_bytes, std::string &out)
{
    out.clear();
    if (end.empty() || !valid())
        return ReadStatus::Closed;

    // 全程持有 r_mtx:与其它 Receive_* / has_data 串行化,
    // 但不影响 send,也不影响 Close(关闭会取消 I/O 并唤醒等待者)
    std::lock_guard<std::mutex> lk(state_->r_mtx);
    if (!state_->is_link.load(std::memory_order_acquire))
        return ReadStatus::Closed;

    // 结束标志可能被 TCP 拆到两次读之间:比较长度上限时要留出 end 本身
    const std::size_t overlap = end.size() - 1;
    // 结束标志还没到、缓存已经超过 max_bytes + overlap 时,一定超限,可以提前拒绝
    const std::size_t hard_limit = (max_bytes == 0) ? 0 : max_bytes + overlap;

    /*
     *@brief 在缓存里找结束标志
     *@param from 起始搜索位置(上次读入前的位置回退 overlap,避免重扫整块缓存)
     */
    auto find_end = [&](std::size_t from)
    {
        if (from > state_->cache.size())
            from = state_->cache.size();
        return std::search(state_->cache.begin() + static_cast<std::ptrdiff_t>(from),
                           state_->cache.end(), end.begin(), end.end());
    };

    // 把 end 之前的数据写入 out,并连同 end 一起从缓存中移除
    auto consume = [&](std::vector<char>::iterator pos)
    {
        out.assign(state_->cache.begin(), pos);
        state_->cache.erase(state_->cache.begin(),
                            pos + static_cast<std::ptrdiff_t>(end.size()));
    };

    // 长度上限:end 之前的数据本身不能超过 max_bytes
    auto too_long = [&](std::vector<char>::iterator pos)
    {
        return max_bytes != 0 &&
               static_cast<std::size_t>(pos - state_->cache.begin()) > max_bytes;
    };

    // 缓存中已存在结束标志
    auto it = find_end(0);
    if (it != state_->cache.end())
    {
        if (too_long(it))
            return ReadStatus::Overflow;
        consume(it);
        return ReadStatus::Ok;
    }

    const bool infinite = (timeout_ms <= 0);
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(infinite ? 0 : timeout_ms);

    while (true)
    {
        // 长度上限:缓存中尚未遇到 end 的字节数
        if (hard_limit != 0 && state_->cache.size() > hard_limit)
            return ReadStatus::Overflow;

        int wait_ms = 0;
        if (!infinite)
        {
            wait_ms = Millis_left(deadline);
            if (wait_ms <= 0)
                return ReadStatus::Timeout;
        }

        char buffer[1024];
        const std::size_t old_size = state_->cache.size();
        int ret = state_->Recv(buffer, sizeof(buffer), wait_ms);
        if (ret > 0)
        {
            state_->cache.insert(state_->cache.end(), buffer, buffer + ret);
            it = find_end(old_size >= overlap ? old_size - overlap : 0);
            if (it != state_->cache.end())
            {
                if (too_long(it))
                    return ReadStatus::Overflow;
                consume(it);
                return ReadStatus::Ok;
            }
        }
        else if (ret == kRecv_timeout)
        {
            return ReadStatus::Timeout;
        }
        else
        {
            state_->MarkDead();
            return ReadStatus::Closed;
        }
    }
}

void Base_Link::Shutdown_send()
{
    if (!state_ || !state_->session)
        return;
    state_->session->shutdown_send();
}

void Base_Link::Drain(int timeout_ms, size_t max_bytes)
{
    if (!state_ || !state_->session || timeout_ms <= 0)
        return;

    std::lock_guard<std::mutex> lk(state_->r_mtx);
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);

    size_t dropped = 0;
    char buffer[4096];
    while (dropped < max_bytes)
    {
        const int remain = Millis_left(deadline);
        if (remain <= 0)
            return;

        const int ret = state_->Recv(buffer, sizeof(buffer), remain);
        if (ret == kRecv_timeout)
            return; // 等不到更多数据:不再等待
        if (ret <= 0)
        {
            state_->MarkDead(); // 对端已关闭或出错
            return;
        }
        dropped += static_cast<size_t>(ret);
    }
}

// ==================== Server ====================

/*
 *@struct Server::Impl
 *@brief 监听与接受连接(异步 accept + 阻塞式取队列)
 */
struct Server::Impl : public std::enable_shared_from_this<Server::Impl>
{
    asio::io_context &io = Io_runtime::instance().context();
    tcp::acceptor acceptor{io};

    std::mutex mtx;
    std::condition_variable cv;
    std::deque<tcp::socket> ready;
    std::atomic<bool> running{false};
    bool closed = false;
    unsigned next_id = 0;

    void accept_one()
    {
        if (closed)
            return;

        auto self = shared_from_this();
        acceptor.async_accept([self](const error_code &ec, tcp::socket socket)
        {
            if (self->closed)
                return;

            if (ec)
            {
                if (ec == asio::error::operation_aborted)
                    return; // 服务器被关闭

                // 瞬时错误(对端在握手前复位、句柄暂时不足等):退避后重试,
                // 不能因此停止接受新连接
                auto timer = std::make_shared<asio::steady_timer>(self->io);
                timer->expires_after(std::chrono::milliseconds(20));
                timer->async_wait([self, timer](const error_code &)
                {
                    self->accept_one();
                });
                return;
            }

            {
                std::lock_guard<std::mutex> lk(self->mtx);
                if (self->closed)
                {
                    error_code ignore;
                    socket.close(ignore);
                    return;
                }
                self->ready.push_back(std::move(socket));
            }
            self->cv.notify_one();
            self->accept_one();
        });
    }
};

Server::Server(unsigned short port, const std::string &bind_address)
{
    impl_ = std::make_shared<Impl>();

    error_code ec;
    const asio::ip::address address = asio::ip::make_address(bind_address, ec);
    if (ec)
    {
        Log::error("Listen socket create failed! Invalid bind address: " + bind_address);
        return;
    }

    tcp::endpoint endpoint(address, port);
    impl_->acceptor.open(endpoint.protocol(), ec);
    if (ec)
    {
        Log::error("Listen socket create failed! Error: " + ec.message());
        return;
    }

    // 允许地址复用,便于快速重启(避免 TIME_WAIT 占用端口)
    impl_->acceptor.set_option(tcp::acceptor::reuse_address(true), ec);

    impl_->acceptor.bind(endpoint, ec);
    if (ec)
    {
        Log::error("Bind failed! Error: " + ec.message());
        return;
    }

    impl_->acceptor.listen(asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        Log::error("Listen failed! Error: " + ec.message());
        return;
    }

    impl_->running.store(true, std::memory_order_release);
    asio::post(impl_->acceptor.get_executor(), [impl = impl_]
    {
        impl->accept_one();
    });
}

Server::~Server()
{
    Close();
}

bool Server::valid() const noexcept
{
    return impl_ && impl_->running.load(std::memory_order_acquire);
}

void Server::Close()
{
    if (!impl_)
        return;

    {
        std::lock_guard<std::mutex> lk(impl_->mtx);
        if (impl_->closed)
            return;
        impl_->closed = true;
        impl_->running.store(false, std::memory_order_release);
        for (auto &socket : impl_->ready)
        {
            error_code ec;
            socket.close(ec);
        }
        impl_->ready.clear();
    }
    impl_->cv.notify_all();

    auto impl = impl_;
    asio::post(impl->acceptor.get_executor(), [impl]
    {
        error_code ec;
        impl->acceptor.cancel(ec);
        impl->acceptor.close(ec);
    });
}

Base_Link Server::get_link()
{
    if (!impl_)
        return {};

    std::unique_lock<std::mutex> lk(impl_->mtx);
    impl_->cv.wait(lk, [this]
    {
        return impl_->closed || !impl_->ready.empty();
    });

    if (impl_->ready.empty())
        return {}; // 服务器已关闭

    tcp::socket socket = std::move(impl_->ready.front());
    impl_->ready.pop_front();
    const unsigned id = ++impl_->next_id;
    lk.unlock();

    return Base_Link(std::make_shared<detail::Session>(std::move(socket), id));
}

} // namespace TCP
