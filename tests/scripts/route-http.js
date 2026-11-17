// 路由回归测试:HTTP 处理器(用于验证同路径 HTTP / WebSocket 共存)
const res = HTTP.send;
res.header("Content-Type", "text/plain; charset=utf-8");
res.text("http-route");
res.send();
