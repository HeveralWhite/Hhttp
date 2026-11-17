// 路由回归测试:undefine_roter 的 WebSocket 兜底处理器
// 用于验证"路径没命中 / 只注册了别的类型"时,兜底处理的 websocket 脚本会被调用
ws.send("fallback-ws");
while (ws.valid()) {
  const msg = ws.recv(2000);
  if (msg === undefined) continue;
  if (msg === null) break;
  ws.send("fallback-echo:" + msg);
}
