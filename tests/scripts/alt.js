// SNI 专用路由:用于验证"多证书按域名选择"是否生效
const res = HTTP.send;
res.header("Content-Type", "text/plain; charset=utf-8");
res.text("hello-alt");
res.send();
