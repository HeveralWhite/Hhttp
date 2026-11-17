// WebSocket 回显
ws.send("hello");
while (ws.valid()) {
  const msg = ws.recv(2000);
  if (msg === undefined) continue; // 超时
  if (msg === null) break;         // 关闭
  if (ws.lastBinary()) ws.sendBinary(msg);
  else ws.send("echo:" + msg);
}
