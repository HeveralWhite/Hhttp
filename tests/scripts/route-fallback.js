// 路由回归测试:undefine_roter 的 HTTP 兜底处理器
// 用 418 明确区分"兜底处理器接管"与"框架默认 404"
const res = HTTP.send;
res.status(418);
res.header("Content-Type", "text/plain; charset=utf-8");
res.text("fallback-http");
res.send();
