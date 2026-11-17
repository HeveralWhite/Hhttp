/*
 * 安全检测脚本示例
 * ----------------------------------------------------------------------------
 * 配置:base_msg.js_security_script = "examples/security.js"
 *
 * 框架在"收到完整请求头、尚未进入路由"时调用 check(req):
 *   req.method       : "GET" / "POST" ...
 *   req.url          : 解码后的路径(不含查询串)
 *   req.rawUrl       : 原始请求目标(未解码,含查询串)
 *   req.version      : "HTTP/1.1" ...
 *   req.header(name)  : 单个请求头(大小写不敏感,不存在返回 "")
 *   req.ip / req.peer: 对端 IP / "IP:端口"
 *   req.cookies()    : 解析后的 Cookie 对象
 *   req.isHttps()    : 当前连接是否 HTTPS(启用 TLS)
 *   req.scheme()     : "https" / "http"
 *   req.tlsProtocol(): 协商出的 TLS 版本(如 "TLS 1.3"),非 TLS 返回 ""
 *
 * 文件 / SQLite 权限(默认全部关闭):
 *   把 base_msg.js_security_script 写成对象即可按 roter 处理器的方式授予权限:
 *   "js_security_script": {
 *       "js_path": "examples/security.js",
 *       "js_read_rule": "data",
 *       "js_write_rule": "data",
 *       "js_sql_read_rule": "data/app.db",
 *       "js_sql_write_rule": "data/app.db",
 *       "js_full_access": false
 *   }
 *   授权后可以使用 File / Sqlite(用法与业务脚本相同);路径相对脚本目录
 *   (--dir),越界、绝对路径与 `..` 一律拒绝。
 *
 * 返回值语义(其余值一律按 500 处理,fail-closed):
 *   true / undefined  : 放行
 *   false             : 拒绝, 403
 *   数字              : 拒绝, 用该数字作状态码
 *   -1                : 静默断开, 不发送状态行 / 响应头 / 正文
 *   { allow: true }   : 放行
 *   { allow: false, status, message, headers } : 拒绝, 按配置回复(headers 只在拒绝时生效)
 *   { close: true }   : 等价于 -1(静默断开)
 *
 * 注意事项:
 *   - 检测脚本运行在请求线程内,必须快速返回;它不注入 HTTP.send,
 *     不能读写响应体;
 *   - 脚本抛异常或返回非法值时按 500 拒绝(不会放行);
 *   - 修改本文件后需要重启进程生效(启动时加载一次)。
 */

// 黑名单 IP(示例)
var banned = ["10.0.0.1", "192.168.1.9"];

function check(req) {
    if (banned.indexOf(req.ip) >= 0) {
        return { allow: false, status: 403, message: "banned" };
    }

    // 常见探测路径直接 404
    if (/\/(\.env|\.git|wp-admin|phpmyadmin)(\/|$)/i.test(req.url)) {
        return 404;
    }

    // 只允许 GET / POST(示例)
    if (req.method !== "GET" && req.method !== "POST") {
        return { allow: false, status: 405, message: "method not allowed" };
    }

    // 放行
    return { allow: true };
}
