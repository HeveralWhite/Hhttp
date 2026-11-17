#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include <string>
#include <vector>
#include <cstdint>

#include "TCP.h"
#include "HTTP.h"

namespace HTTP
{
/*
 *@class WebSocket
 *@brief 基于 RFC 6455 的 WebSocket 服务器端实现(封装一条 TCP 连接)
 *
 * 典型用法:
 *   在 Distributor 的 WebSocket 处理器中:
 *       std::string msg; bool binary = false;
 *       while (ws.Recv(msg, binary))
 *           ws.SendText("echo: " + msg);
 */
class WebSocket
{
public:
    enum class Opcode : uint8_t
    {
        Continuation = 0x0,
        Text = 0x1,
        Binary = 0x2,
        Close = 0x8,
        Ping = 0x9,
        Pong = 0xA
    };

    WebSocket() = default;
    explicit WebSocket(TCP::Base_Link link);

    /*
     *@brief 服务器端握手:校验升级请求并回发 101 Switching Protocols
     *@param link 底层连接
     *@param request 已解析的升级请求
     *@return 握手是否成功
     */
    static bool Handshake(TCP::Base_Link &link, const Header_get &request);

    /*
     *@brief 连接是否仍然打开
     */
    bool valid() const;

    /*
     *@brief 发送关闭帧并关闭底层连接
     */
    void Close(uint16_t code = 1000, const std::string &reason = "");

    bool SendText(const std::string &msg);
    bool SendBinary(const std::vector<char> &data);
    bool SendPing(const std::string &payload = "");
    bool SendPong(const std::string &payload = "");

    /*
     *@brief RecvEx 的返回状态
     */
    enum class RecvStatus
    {
        Message, ///< 成功收到一条应用层消息
        Timeout, ///< 超时(连接仍然有效,可继续收发)
        Closed,  ///< 对端已关闭连接
        Error    ///< 协议错误
    };

    /*
     *@brief 接收一条完整的应用层消息
     *       内部会自动处理分片、Ping/Pong,并在收到 Close 时返回 false
     *@param out 收到的消息内容
     *@param is_binary 收到的消息是否为二进制帧
     *@param timeout_ms 超时(毫秒),0 表示无限等待
     *@return 成功收到一条消息返回 true;连接关闭/出错/超时返回 false
     */
    bool Recv(std::string &out, bool &is_binary, int timeout_ms = 0);

    /*
     *@brief 与 Recv 相同,但能区分“超时”与“关闭”
     *       聊天类服务需要在等待输入的同时向客户端推送广播:
     *       用较短的 timeout_ms 轮询,超时后继续处理其它消息
     */
    RecvStatus RecvEx(std::string &out, bool &is_binary, int timeout_ms = 0);

    TCP::Base_Link &link() {
        return link_;
    }
    const TCP::Base_Link &link() const {
        return link_;
    }

private:
    // 底层 I/O 结果
    enum class IoStatus
    {
        Ok,      ///< 成功
        Timeout, ///< 数据不完整且超时(接收缓冲原样保留,可重试)
        Closed,  ///< 连接已关闭
        Error    ///< 协议错误
    };

    bool SendFrame(Opcode op, const char *data, size_t len, bool fin = true);
    /*
     *@brief 确保接收缓冲区中至少有 n 字节(不消费数据)
     */
    IoStatus Ensure(size_t n, int timeout_ms);
    /*
     *@brief 解析一个完整的帧
     *@note  失败(超时/关闭)时不消费接收缓冲区,下次可安全重试,
     *       避免半个帧被丢弃后造成后续帧错位
     */
    IoStatus ReadFrame(Opcode &op, bool &fin, std::vector<char> &payload,
                       int timeout_ms);

    TCP::Base_Link link_;
    bool open_ = false;

    std::vector<char> rx_buffer_;   // 接收缓冲区(可能含不足一帧的数据)
    std::vector<char> frag_buffer_; // 分片消息累积区
    bool frag_binary_ = false;      // 当前分片消息是否为二进制
    bool frag_started_ = false;     // 是否处于分片消息中
};
}

#endif // WEBSOCKET_H
