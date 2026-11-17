// 流式响应(chunked)
const res = HTTP.send;
const n = Number(HTTP.get.query().n || 3);
res.header("Content-Type", "text/plain; charset=utf-8");
res.beginStream();
for (let i = 0; i < n; i++) res.chunk("chunk-" + i + ";");
res.endStream();
