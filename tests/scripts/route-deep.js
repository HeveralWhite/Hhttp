// 路由回归测试:*.wild.test 域名表(比 *.test 更具体的通配,应当优先命中)
const res = HTTP.send;
res.header("Content-Type", "text/plain; charset=utf-8");
res.text("route-deep");
res.send();
