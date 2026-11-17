#include "Log.h"

#include <fstream>
#include <iostream>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <cstdint>
#include <thread>
#include <utility>
#include <filesystem>
#include <system_error>
#include <algorithm>
#include <cstddef>
#include <string>

namespace
{
std::queue<Log::Log_msg> log_queue;
std::mutex queue_mutex;
std::condition_variable queue_cv;
std::atomic<bool> running{false};
std::atomic<bool> colorful_output{true}; // 是否输出 ANSI 颜色(由 base_msg.colorful_log 控制)
std::thread output_thread;
const std::string log_dir = "LOG";

/*
 * 日志队列的积压上限。
 *
 * 生产环境里日志线程要写控制台和磁盘,吞吐远低于"请求产生日志"的速度:
 * 对端刷请求(每请求 2~3 条访问日志)或在脚本里 console.log 死循环,都能让
 * 队列无限增长直到把进程内存吃光。这里给一个足够大的上限,超出时丢弃新日志
 * 并计数,由日志线程在下一轮补一条"丢弃了多少条"的提示 —— 既不拖垮进程,
 * 也不会悄悄丢日志。
 */
constexpr std::size_t k_max_pending = 100000;
std::atomic<std::uint64_t> g_dropped{0};

// 访问日志（连接/请求/响应/WebSocket）使用独立文件，避免高频记录淹没关键日志
// 按日志类型选择落盘文件:访问日志 -> LOG/access.<date>.txt，其余 -> LOG/<date>.txt
std::string log_file_path(bool access_log, const std::string &date)
{
    if (access_log)
        return log_dir + "/access." + date + ".txt";
    return log_dir + "/" + date + ".txt";
}

void ensure_log_dir()
{
    std::error_code ec;
    std::filesystem::create_directories(log_dir, ec);
}

/*
 *@brief 落盘文件句柄缓存:同一类日志只保留一个打开的 ofstream
 *@note  旧实现每条日志都 ofstream(path, app) -> write -> close,一秒钟几千条日志时
 *       open/close 的系统调用开销会完全盖过日志本身。这里把句柄缓存起来
 *       (跨天时路径变化,自动切换到新文件),每行仍显式 flush,保证崩溃前的
 *       日志不会丢在用户态缓冲里。
 *       打开失败时清掉缓存,下一条日志会重新尝试;文件日志失败不影响控制台。
 */
class File_sink
{
public:
    bool Write(const std::string &path, const std::string &text)
    {
        if (path_ != path)
        {
            if (out_.is_open())
                out_.close();
            out_.clear();
            out_.open(path, std::ios::app);
            path_ = path;
        }
        if (!out_.is_open())
        {
            path_.clear(); // 打开失败:下一次重新尝试
            return false;
        }

        out_ << text;
        out_.flush();
        if (!out_)
        {
            out_.close();
            path_.clear();
            return false;
        }
        return true;
    }

    void Close()
    {
        if (out_.is_open())
            out_.close();
        path_.clear();
    }

private:
    std::ofstream out_;
    std::string path_;
};

File_sink main_sink;   ///< 框架主日志 LOG/<date>.txt
File_sink access_sink; ///< 访问日志 LOG/access.<date>.txt

// 线程安全地将时间戳格式化为本地时间字符串(仅用 C 标准库，不依赖平台专有 API)
std::string format_local_time(time_t now, const char *fmt)
{
    std::tm tm_buf{};
    {
        static std::mutex tm_mutex;
        std::lock_guard<std::mutex> lock(tm_mutex);
        std::tm *local = std::localtime(&now);
        if (local == nullptr)
            return std::string();
        tm_buf = *local;
    }

    char buffer[80];
    std::strftime(buffer, sizeof(buffer), fmt, &tm_buf);
    return std::string(buffer);
}

/*
 *@brief 秒级时间文本缓存
 *@note  同一秒内的日志共用一次 localtime + strftime 的结果。时间戳本身精度就是
 *       秒,所以缓存不会改变任何一行日志的内容;连续日志(高并发下几乎都是同一秒)
 *       可以省掉每条日志两次时间格式化。
 *       只在日志线程里使用,不需要加锁。
 */
struct Time_text_cache
{
    bool valid = false;
    std::time_t ts = 0;
    std::string stamp; ///< "YYYY.MM.DD HH:MM:SS"
    std::string date;  ///< "YYYY.MM.DD"
};

Time_text_cache g_time_cache;

const Time_text_cache &time_text(std::time_t ts)
{
    if (!g_time_cache.valid || g_time_cache.ts != ts)
    {
        g_time_cache.ts = ts;
        g_time_cache.stamp = format_local_time(ts, "%Y.%m.%d %H:%M:%S");
        g_time_cache.date = format_local_time(ts, "%Y.%m.%d");
        g_time_cache.valid = true;
    }
    return g_time_cache;
}

/*
 *@brief 单次 std::cout 写入的长度上限
 *@note  Windows 控制台对单次写入的长度是有限制的(约 64 KiB),超出时这次写入
 *       会失败并把 std::cout 置成 badbit;分片写入可以从根上避开这个限制。
 */
constexpr std::size_t k_console_chunk = 4096;

/*
 *@brief 生成 ANSI SGR 前景色转义序列
 *@note  彩色输出关闭时返回空串:handle_output / set_color 无需自己判断开关，
 *       也不会向控制台写入任何转义序列
 */
std::string sgr(Log::Color item)
{
    if (!colorful_output.load())
        return std::string();
    return "\033[" + std::to_string(static_cast<int>(item)) + "m";
}

/*
 *@brief 把一段文本写到 std::cout:进程内唯一直接写控制台的入口
 *@note  1) 写入前复位上一轮遗留的 badbit/failbit,
 *          避免一次失败导致之后所有控制台输出永久静默;
 *       2) 分片写入,避免超长行(例如脚本 console.log 打印大对象)
 *          触发 Windows 控制台的单次写入上限;
 *       3) 吞掉流上可能被设置的异常掩码,日志线程不会因为写失败而终止。
 *       控制台写不出去时只丢这一条,文件日志不受影响。
 */
void console_write(const std::string &text)
{
    if (!std::cout.good())
        std::cout.clear();

    try
    {
        std::size_t offset = 0;
        while (offset < text.size())
        {
            const std::size_t chunk = std::min(k_console_chunk, text.size() - offset);
            std::cout.write(text.data() + offset, static_cast<std::streamsize>(chunk));
            if (!std::cout)
            {
                // 控制台不可写(句柄失效 / 被重定向到已关闭的管道等):
                // 复位状态位,下一条日志继续尝试
                std::cout.clear();
                return;
            }
            offset += chunk;
        }
    }
    catch (...)
    {
        // 流上开了异常掩码时也不要让输出线程挂掉
        std::cout.clear();
    }
}

/*
 *@brief 输出一条日志(控制台 + 落盘)
 *@param access 是否写访问日志文件
 *@note  同一行只取一次时间文本,控制台与文件共用
 */
void emit(Log::Color color, const std::string &title, const std::string &text,
          std::time_t ts, bool access)
{
    const Time_text_cache &time = time_text(ts);

    std::string line;
    line.reserve(text.size() + title.size() + 48);
    line += sgr(Log::Color::White);
    line += "[";
    line += time.stamp;
    line += "] ";
    line += sgr(color);
    line += "[";
    line += title;
    line += "] ";
    line += sgr(Log::Color::White);
    line += text;
    line += "\n";
    console_write(line);

    if (title == "DEBUG") // 调试信息不输出到文件
        return;

    std::string record;
    record.reserve(line.size());
    record += "[";
    record += time.stamp;
    record += "] [";
    record += title;
    record += "] ";
    record += text;
    record += "\n";

    File_sink &sink = access ? access_sink : main_sink;
    sink.Write(log_file_path(access, time.date), record);
}

void push_log(Log::Log_msg msg)
{
    bool dropped = false;
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        // 队列积压到上限时丢弃新日志(宁可丢日志也不能把进程内存吃光)
        if (log_queue.size() >= k_max_pending)
        {
            g_dropped.fetch_add(1, std::memory_order_relaxed);
            dropped = true;
        }
        else
        {
            log_queue.push(std::move(msg));
        }
    }
    if (!dropped)
        queue_cv.notify_one();
}

void handle_output()
{
    ensure_log_dir();

    while (true)
    {
        Log::Log_msg item;
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            queue_cv.wait(lock, []
            { return !log_queue.empty() || !running.load(); });

            if (log_queue.empty())
            {
                // 只有在停止且队列排空时才退出;运行期间的唤醒可能只是 notify
                if (!running.load())
                    break;
                continue;
            }

            item = std::move(log_queue.front());
            log_queue.pop();
            // 锁外输出:控制台/磁盘 I/O 不阻塞其它线程写日志
        }

        emit(item.color, item.title, item.log, item.timestamp, item.access_log);

        // 上一轮因为队列满而丢掉的日志条数:补一条提示(不静默丢弃)
        const std::uint64_t dropped = g_dropped.exchange(0, std::memory_order_relaxed);
        if (dropped > 0)
        {
            emit(Log::Color::Red, "LOG",
                 std::to_string(dropped) + " log message(s) dropped: queue is full",
                 std::time(nullptr), false);
        }
    }

    // 退出前把文件缓冲刷干净
    main_sink.Close();
    access_sink.Close();
}

struct OutputStopper
{
    ~OutputStopper()
    {
        Log::stop_output();
    }
};
OutputStopper output_stopper;

} // anonymous namespace

namespace Log
{

void set_colorful(bool enable)
{
    // 只影响控制台着色:落盘文件日志本就不含转义序列
    colorful_output.store(enable);
}

bool colorful() noexcept
{
    return colorful_output.load();
}

void set_color(Color item)
{
    // 直接输出 ANSI SGR 前景色转义序列，不依赖平台专有 API
    // 统一走 console_write,避免绕过状态自愈
    // 彩色输出关闭时 sgr() 返回空串,这里不会写入任何内容
    console_write(sgr(item));
}

/*
 *@brief 文本是否需要清洗(没有 CR/LF 与控制字符)
 */
bool text_is_clean(const std::string &text) noexcept
{
    for (const unsigned char ch : text)
    {
        if (ch == '\r' || ch == '\n' || ch < 0x20 || ch == 0x7F)
            return false;
    }
    return true;
}

void error(std::string msg)
{
    push_log({std::time(0), Color::Red, "ERROR", std::move(msg)});
}

void warning(std::string msg)
{
    push_log({std::time(0), Color::Yellow, "WARNING", std::move(msg)});
}

void log(std::string msg, Color item, const std::string &title)
{
    push_log({std::time(0), item, title, std::move(msg)});
}

void access(std::string msg, Color item, const std::string &title)
{
    push_log({std::time(0), item, title, std::move(msg), true});
}

void debug(std::string msg)
{
    push_log({std::time(0), Color::LightGray, "DEBUG", std::move(msg)});
}

std::string get_tim(time_t now)
{
    return format_local_time(now, "%Y.%m.%d %H:%M:%S");
}

std::string get_date(int day)
{
    std::time_t now = std::time(0) + static_cast<std::time_t>(day) * 86400;
    return format_local_time(now, "%Y.%m.%d");
}

void append_sanitized(std::string &out, const std::string &text)
{
    // 常见情况:文本本来就是干净的(URL / Host / 状态短语几乎总是),直接追加
    if (text_is_clean(text))
    {
        out += text;
        return;
    }

    for (const unsigned char ch : text)
    {
        if (ch == '\r')
            continue; // 行尾的 CR 直接丢掉,避免 "空格 + CR" 残留
        if (ch == '\n')
        {
            out.push_back(' ');
            continue;
        }
        if (ch < 0x20 || ch == 0x7F)
        {
            // 其余控制字符(含 ANSI ESC):替换掉,防止伪造日志行/终端控制序列
            out.push_back('?');
            continue;
        }
        out.push_back(static_cast<char>(ch));
    }
}

std::string sanitize(const std::string &text)
{
    if (text_is_clean(text))
        return text;

    std::string out;
    out.reserve(text.size());
    append_sanitized(out, text);
    return out;
}

void start_output()
{
    static std::atomic<bool> started{false};
    bool expected = false;
    if (!started.compare_exchange_strong(expected, true))
    {
        return;
    }

    // 控制台写入失败不应该以异常形式打断日志线程:
    // 这里把异常掩码清零(failbit/badbit 只置位,由 console_write 负责复位)
    std::cout.exceptions(std::ios::goodbit);
    if (!std::cout.good())
        std::cout.clear();

    running.store(true);
    output_thread = std::thread(handle_output);
    log("Log output thread start!", Color::Green, "LOG");
}

void stop_output()
{
    if (running.exchange(false))
    {
        queue_cv.notify_all();
        if (output_thread.joinable())
        {
            output_thread.join();
        }
    }
}

} // namespace Log
