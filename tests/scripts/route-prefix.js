// 路由回归测试:精确域名下的前缀路由 "/"
const res = HTTP.send;
res.header("Content-Type", "text/plain; charset=utf-8");
res.text("route-prefix");
res.send();
