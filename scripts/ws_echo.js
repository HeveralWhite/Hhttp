/*
 * Hhttp WebSocket 回显示例
 * ----------------------------------------------------------------------------
 * 配置:config.example.json 中 "/ws" 路由指向本文件。
 *
 * 行为:
 *   - 握手完成后先发一条欢迎语;
 *   - 之后循环接收消息:文本回 "echo: <内容>",二进制原样回送;
 *   - ws.recv() 超时返回 undefined(这里继续等待),对端关闭返回 null(退出循环)。
 *
 * 用浏览器控制台快速验证:
 *   const s = new WebSocket("ws://127.0.0.1:8080/ws");
 *   s.onmessage = e => console.log(e.data);
 *   s.onopen = () => s.send("hello");
 */

ws.send("welcome, " + ws.peer());

while (ws.valid()) {
    const msg = ws.recv(1000);   // 1 秒超时:不阻塞关闭流程
    if (msg === undefined) {
        continue;                // 空闲:真实业务里可在这里做定时推送
    }
    if (msg === null) {
        break;                   // 对端关闭
    }
    if (ws.lastBinary()) {
        ws.sendBinary(msg);
    } else {
        ws.send("echo: " + msg);
    }
}
