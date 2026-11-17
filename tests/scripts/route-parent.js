// 路由回归测试:*.test 域名表(较宽的通配)
const res = HTTP.send;
res.header("Content-Type", "text/plain; charset=utf-8");
res.text("route-parent");
res.send();
