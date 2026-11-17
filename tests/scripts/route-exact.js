// 路由回归测试:精确域名 + 精确路径
const res = HTTP.send;
res.header("Content-Type", "text/plain; charset=utf-8");
res.text("exact-route");
res.send();
