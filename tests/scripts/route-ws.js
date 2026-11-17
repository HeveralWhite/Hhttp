// 路由回归测试:WebSocket 处理器
ws.send("ws-route");
while (ws.valid()) {
  const msg = ws.recv(2000);
  if (msg === undefined) continue; // 超时
  if (msg === null) break;         // 关闭
  ws.send("echo:" + msg);
}
