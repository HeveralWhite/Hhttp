// 定长响应体:用于 GET / HEAD 的 Content-Length 一致性检查
const res = HTTP.send;
res.header("Content-Type", "text/plain; charset=utf-8");
res.text("hello-static");
res.send();
