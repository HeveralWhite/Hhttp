/*
 * Hhttp 最小示例脚本
 * ----------------------------------------------------------------------------
 * 配置:config.example.json 中 "/" 路由指向本文件(js_path = "hello.js")。
 *
 * 演示内容:
 *   GET  /            返回一个自包含的 HTML 页面(含本次请求信息)
 *   GET  /api/time    返回 JSON:服务器时间、HTTPS/Scheme、TLS 版本
 *   *    /api/echo    回显请求方法、查询参数、请求头、Cookie 与请求体
 *
 * 约定:每个请求都会新建一个隔离的 JS 运行时,脚本之间不共享全局变量;
 *       HTTP 脚本必须显式调用 HTTP.send.send() 才会发送响应。
 */

const req = HTTP.get;
const res = HTTP.send;
const path = req.url();

/*
 * 统一出口:先由分支设置状态码 / 响应头 / 响应体,最后在这里调用 send()。
 */
function finish() {
    res.send();
}

if (path === "/api/time") {
    res.json({
        ok: true,
        now: Date.now(),
        iso: new Date().toISOString(),
        scheme: req.scheme(),
        isHttps: req.isHttps(),
        tls: req.tlsProtocol()
    });
    finish();
} else if (path.indexOf("/api/echo") === 0) {
    res.json({
        method: req.method(),
        url: path,
        rawUrl: req.rawUrl(),
        version: req.version(),
        query: req.query(),
        headers: req.headers(),
        cookies: req.cookies(),
        ip: req.ip(),
        peer: req.peer(),
        body: req.body()
    });
    finish();
} else {
    // 示例 Cookie:httpOnly 防 XSS 读取;secure 仅在 HTTPS 下生效
    const visit = new Cookie("hhttp_demo", String(Date.now()));
    visit.httpOnly = true;
    visit.path = "/";
    visit.sameSite = "Lax";
    visit.secure = req.isHttps();
    res.cookie(visit);

    res.header("Cache-Control", "no-store");
    res.html(
        "<!DOCTYPE html>\n" +
        "<html lang=\"zh-CN\"><head><meta charset=\"utf-8\">\n" +
        "<title>Hello Hhttp</title>\n" +
        "<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:48px auto;padding:0 16px;line-height:1.7}" +
        "code{background:#f2f2f2;padding:2px 6px;border-radius:4px}table{border-collapse:collapse;width:100%}" +
        "td,th{border:1px solid #ddd;padding:6px 10px;text-align:left;font-size:14px}</style></head><body>\n" +
        "<h1>Hello Hhttp</h1>\n" +
        "<p>这个页面由 <code>scripts/hello.js</code> 生成,说明服务器、路由与 QuickJS 已正常工作。</p>\n" +
        "<table>\n" +
        "<tr><th>项目</th><th>值</th></tr>\n" +
        "<tr><td>方法 / 路径</td><td><code>" + req.method() + " " + path + "</code></td></tr>\n" +
        "<tr><td>HTTP 版本</td><td><code>" + req.version() + "</code></td></tr>\n" +
        "<tr><td>对端</td><td><code>" + req.peer() + "</code></td></tr>\n" +
        "<tr><td>Scheme</td><td><code>" + req.scheme() + "</code></td></tr>\n" +
        "<tr><td>TLS</td><td><code>" + (req.tlsProtocol() || "未启用") + "</code></td></tr>\n" +
        "<tr><td>User-Agent</td><td><code>" + req.header("user-agent") + "</code></td></tr>\n" +
        "</table>\n" +
        "<h2>试试这些接口</h2>\n" +
        "<ul>\n" +
        "<li><a href=\"/api/time\">/api/time</a> -- 服务器时间与连接信息</li>\n" +
        "<li><a href=\"/api/echo?name=hhttp&amp;lang=js\">/api/echo?name=hhttp&amp;lang=js</a> -- 请求回显</li>\n" +
        "</ul>\n" +
        "<h2>WebSocket</h2>\n" +
        "<p>同一份配置把 <code>/ws</code> 交给 <code>ws_echo.js</code>:连接后发送任意文本,服务器会回 <code>echo: ...</code>。</p>\n" +
        "</body></html>"
    );
    finish();
}
