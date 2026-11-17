#include "WebSocket.h"
#include "Log.h"

#include <algorithm>
#include <cstring>

namespace
{
// WebSocket 协议规定的魔法 GUID
constexpr char kWebSocketGuid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// 单帧 payload 上限(与 ReadFrame 里的检查保持一致)
constexpr uint64_t kMaxFrameSize = 16ull * 1024 * 1024;
// 分片消息重组后的总长度上限。
// 没有这个上限时,客户端可以发无数个合法的 continuation 帧,
// frag_buffer_ 会一直膨胀,单个连接就能把进程内存吃光。
constexpr size_t kMaxMessageSize = 16u * 1024 * 1024;
// 控制帧(Close / Ping / Pong)的 payload 上限(RFC 6455 §5.5)
constexpr size_t kMaxControlPayload = 125;

// 计算 Sec-WebSocket-Accept
std::string ComputeAcceptKey(const std::string &client_key)
{
    return HTTP::base64_encode(HTTP::sha1(client_key + kWebSocketGuid));
}
}

namespace HTTP
{
WebSocket::WebSocket(TCP::Base_Link link) : link_(std::move(link))
{
    open_ = link_.valid();
}

bool WebSocket::Handshake(TCP::Base_Link &link, const Header_get &request)
{
    const std::string peer = link.get_peer();

    if (!request.is_websocket())
    {
        Log::warning("WebSocket handshake: not an upgrade request. (" +
                     request.method + " " + request.raw_url +
                     ", peer: " + peer + ")");
        return false;
    }

    std::string key = request.get("sec-websocket-key");
    if (key.empty())
    {
        Log::warning("WebSocket handshake: missing Sec-WebSocket-Key. (" +
                     request.raw_url + ", peer: " + peer + ")");
        Header_send::Status(400, "Missing Sec-WebSocket-Key").send(link);
        return false;
    }

    std::string accept = ComputeAcceptKey(key);

    std::string response =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: " +
        accept + "\r\n"
             "\r\n";

    link.Send_str(response);

    // 访问日志:握手成功(携带路径与来源)，失败则记录告警
    const bool ok = link.valid();
    if (ok)
    {
        // raw_url 来自网络:压成单行,避免换行伪造日志
        Log::access("WebSocket connected: " + Log::sanitize(request.raw_url) +
                    " (peer: " + peer + ")",
                    Log::Color::LightCyan, "WS");
    }
    else
    {
        Log::warning("WebSocket handshake response send failed. (" +
                     Log::sanitize(request.raw_url) + ", peer: " + peer + ")");
    }
    return ok;
}

bool WebSocket::valid() const
{
    return open_ && link_.valid();
}

bool WebSocket::SendFrame(Opcode op, const char *data, size_t len, bool fin)
{
    if (!link_.valid())
        return false;

    std::vector<char> frame;
    frame.reserve(len + 10);

    // 第一个字节: FIN + opcode (服务器发送的帧不设置 RSV)
    frame.push_back(static_cast<char>((fin ? 0x80 : 0x00) |
                                      static_cast<uint8_t>(op)));

    // 第二个字节: MASK = 0 (服务器 -> 客户端 不加掩码) + payload length
    if (len < 126)
    {
        frame.push_back(static_cast<char>(len));
    }
    else if (len <= 0xFFFF)
    {
        frame.push_back(static_cast<char>(126));
        frame.push_back(static_cast<char>((len >> 8) & 0xFF));
        frame.push_back(static_cast<char>(len & 0xFF));
    }
    else
    {
        frame.push_back(static_cast<char>(127));
        for (int i = 7; i >= 0; --i)
            frame.push_back(static_cast<char>((len >> (i * 8)) & 0xFF));
    }

    if (len > 0 && data)
        frame.insert(frame.end(), data, data + len);

    link_.Send_sb(frame);
    return link_.valid();
}

bool WebSocket::SendText(const std::string &msg)
{
    return SendFrame(Opcode::Text, msg.data(), msg.size(), true);
}

bool WebSocket::SendBinary(const std::vector<char> &data)
{
    return SendFrame(Opcode::Binary, data.data(), data.size(), true);
}

bool WebSocket::SendPing(const std::string &payload)
{
    // 控制帧 payload 不能超过 125 字节,超了就是非法帧
    if (payload.size() > kMaxControlPayload)
        return false;
    return SendFrame(Opcode::Ping, payload.data(), payload.size(), true);
}

bool WebSocket::SendPong(const std::string &payload)
{
    if (payload.size() > kMaxControlPayload)
        return false;
    return SendFrame(Opcode::Pong, payload.data(), payload.size(), true);
}

void WebSocket::Close(uint16_t code, const std::string &reason)
{
    // 已关闭过则直接返回，避免重复记录关闭日志
    if (!open_ && !link_.valid())
        return;

    const std::string peer = link_.get_peer();
    const bool can_send = open_ && link_.valid();

    if (can_send)
    {
        // 关闭帧的 payload 上限是 125 字节(2 字节状态码 + 最多 123 字节原因),
        // 原因过长时截断,否则会发出一条非法帧
        const std::string text =
            reason.size() > kMaxControlPayload - 2
            ? reason.substr(0, kMaxControlPayload - 2) : reason;

        std::vector<char> payload;
        payload.reserve(2 + text.size());
        payload.push_back(static_cast<char>((code >> 8) & 0xFF));
        payload.push_back(static_cast<char>(code & 0xFF));
        payload.insert(payload.end(), text.begin(), text.end());
        SendFrame(Opcode::Close, payload.data(), payload.size(), true);

        /*
         * 关闭前的收尾:先半关闭写方向(把关闭帧连同 FIN 交给对端),再短暂排空
         * 对端可能还在路上的数据。直接 Close() 时如果接收缓冲区里还有未读数据,
         * Windows 会用 RST 关闭连接,对端可能因此根本收不到刚发出的关闭帧。
         */
        link_.Shutdown_send();
        link_.Drain(150);
    }
    open_ = false;
    link_.Close();

    if (can_send)
    {
        Log::access("WebSocket closed: " + peer + " (code: " +
                    std::to_string(code) + ", reason: " +
                    (reason.empty() ? "none" : Log::sanitize(reason)) + ")",
                    Log::Color::DarkGray, "WS");
    }
    else
    {
        Log::access("WebSocket disconnected: " + peer +
                    " (peer already gone, close frame not sent)",
                    Log::Color::DarkGray, "WS");
    }
}

WebSocket::IoStatus WebSocket::Ensure(size_t n, int timeout_ms)
{
    while (rx_buffer_.size() < n)
    {
        if (!link_.valid())
            return IoStatus::Closed;

        std::vector<char> chunk =
            link_.Receive_sb(n - rx_buffer_.size(), timeout_ms);

        if (chunk.empty())
        {
            // Receive_sb 在“超时”与“连接关闭”时都可能返回空,
            // 用连接的可用性来区分
            return link_.valid() ? IoStatus::Timeout : IoStatus::Closed;
        }

        rx_buffer_.insert(rx_buffer_.end(), chunk.begin(), chunk.end());
    }
    return IoStatus::Ok;
}

WebSocket::IoStatus WebSocket::ReadFrame(Opcode &op, bool &fin,
        std::vector<char> &payload,
        int timeout_ms)
{
    // 1) 先保证 2 字节基础头到齐(只窥视,不消费)
    IoStatus st = Ensure(2, timeout_ms);
    if (st != IoStatus::Ok)
        return st;

    auto buffer = [this]()
    {
        return reinterpret_cast<const unsigned char *>(rx_buffer_.data());
    };

    if (buffer()[0] & 0x70)
        return IoStatus::Error; // RSV1/2/3 必须为 0(本实现不支持扩展)

    fin = (buffer()[0] & 0x80) != 0;
    op = static_cast<Opcode>(buffer()[0] & 0x0F);

    const bool masked = (buffer()[1] & 0x80) != 0;
    /*
     * RFC 6455 §5.1:客户端发往服务器的帧必须加掩码,服务器发现未加掩码的帧
     * 必须使连接失败。放过它等于接受"任意 HTTP 客户端伪装成 WebSocket",
     * 也是跨协议攻击的常见入口。
     */
    if (!masked)
        return IoStatus::Error;

    uint64_t len = buffer()[1] & 0x7F;
    size_t header_len = 2;

    // 2) 扩展长度
    if (len == 126)
    {
        st = Ensure(4, timeout_ms);
        if (st != IoStatus::Ok)
            return st;
        len = (static_cast<uint64_t>(buffer()[2]) << 8) | buffer()[3];
        header_len = 4;
    }
    else if (len == 127)
    {
        st = Ensure(10, timeout_ms);
        if (st != IoStatus::Ok)
            return st;
        len = 0;
        for (int i = 0; i < 8; ++i)
            len = (len << 8) | buffer()[2 + i];
        header_len = 10;
    }

    // 防止恶意超大帧耗尽内存
    if (len > kMaxFrameSize)
        return IoStatus::Error;

    // 控制帧不允许分片,且 payload 最多 125 字节(否则可直接用它占内存)
    const bool control = (static_cast<uint8_t>(op) & 0x08) != 0;
    if (control && (!fin || len > kMaxControlPayload))
        return IoStatus::Error;

    const size_t mask_len = masked ? 4 : 0;
    const size_t total = header_len + mask_len + static_cast<size_t>(len);

    // 3) 整帧到齐后一次性取出
    st = Ensure(total, timeout_ms);
    if (st != IoStatus::Ok)
        return st;

    unsigned char mask[4] = {0, 0, 0, 0};
    if (masked)
        std::memcpy(mask, buffer() + header_len, 4);

    payload.resize(static_cast<size_t>(len));
    if (len > 0)
        std::memcpy(payload.data(), buffer() + header_len + mask_len,
                    static_cast<size_t>(len));

    // 客户端发往服务器的帧必须加掩码,这里做解掩码
    if (masked)
        for (size_t i = 0; i < payload.size(); ++i)
            payload[i] = static_cast<char>(
                             static_cast<unsigned char>(payload[i]) ^ mask[i % 4]);

    // 消费掉这一帧
    rx_buffer_.erase(rx_buffer_.begin(),
                     rx_buffer_.begin() + static_cast<std::ptrdiff_t>(total));
    return IoStatus::Ok;
}

WebSocket::RecvStatus WebSocket::RecvEx(std::string &out, bool &is_binary,
                                        int timeout_ms)
{
    out.clear();
    is_binary = false;

    while (true)
    {
        Opcode op;
        bool fin = false;
        std::vector<char> payload;

        IoStatus st = ReadFrame(op, fin, payload, timeout_ms);
        if (st == IoStatus::Timeout)
            return RecvStatus::Timeout;
        if (st == IoStatus::Closed)
            return RecvStatus::Closed;
        if (st == IoStatus::Error)
            return RecvStatus::Error;

        switch (op)
        {
        case Opcode::Ping:
            // 收到 Ping 自动回 Pong
            SendFrame(Opcode::Pong, payload.data(), payload.size(), true);
            continue;

        case Opcode::Pong:
            continue;

        case Opcode::Close:
        {
            // 解析对端的关闭码与原因(便于排查)后回一个关闭帧并终止
            uint16_t peer_code = 0;
            std::string peer_reason;
            if (payload.size() >= 2)
            {
                peer_code = static_cast<uint16_t>(
                                (static_cast<unsigned char>(payload[0]) << 8) |
                                static_cast<unsigned char>(payload[1]));
                peer_reason.assign(payload.begin() + 2, payload.end());
            }
            // 关闭原因来自对端:压成单行,避免换行伪造日志
            Log::access("WebSocket close frame received: " + link_.get_peer() +
                        " (code: " + std::to_string(peer_code) + ", reason: " +
                        (peer_reason.empty() ? "none" : Log::sanitize(peer_reason)) + ")",
                        Log::Color::DarkGray, "WS");

            /*
             * 回显关闭帧时必须保证自己发出去的是合法帧:
             * payload 只有 1 字节是非法长相(不能有"只有一半的状态码"),
             * 原样回显会构造出畸形帧,这里改回 1002(protocol error)。
             */
            if (payload.size() == 1)
            {
                const unsigned char code[2] = {0x03, 0xEA}; // 1002
                SendFrame(Opcode::Close, reinterpret_cast<const char *>(code), 2, true);
            }
            else if (!payload.empty())
            {
                SendFrame(Opcode::Close, payload.data(), payload.size(), true);
            }
            else
            {
                SendFrame(Opcode::Close, nullptr, 0, true);
            }
            // 同 Close():先半关闭并排空,避免未读数据触发 RST 冲掉关闭帧
            link_.Shutdown_send();
            link_.Drain(150);
            open_ = false;
            link_.Close();
            return RecvStatus::Closed;
        }

        case Opcode::Text:
        case Opcode::Binary:
            // 上一条分片消息还没结束就又来了一条新消息:协议错误
            if (frag_started_)
                return RecvStatus::Error;
            frag_buffer_ = std::move(payload);
            frag_binary_ = (op == Opcode::Binary);
            frag_started_ = true;
            break;

        case Opcode::Continuation:
            if (!frag_started_)
                return RecvStatus::Error; // 协议错误:没有起始帧
            // 重组上限:否则对端可以用无限多个合法分片把内存吃光
            if (frag_buffer_.size() + payload.size() > kMaxMessageSize)
                return RecvStatus::Error;
            frag_buffer_.insert(frag_buffer_.end(), payload.begin(), payload.end());
            break;

        default:
            return RecvStatus::Error; // 未知 opcode
        }

        if (fin)
        {
            out.assign(frag_buffer_.begin(), frag_buffer_.end());
            is_binary = frag_binary_;
            frag_buffer_.clear();
            frag_started_ = false;
            return RecvStatus::Message;
        }
    }
}

bool WebSocket::Recv(std::string &out, bool &is_binary, int timeout_ms)
{
    return RecvEx(out, is_binary, timeout_ms) == RecvStatus::Message;
}
} // namespace HTTP
