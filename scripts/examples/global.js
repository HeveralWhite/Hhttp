/*
 * 全局数据脚本示例
 * ----------------------------------------------------------------------------
 * 配置:base_msg.js_global_script = "examples/global.js"
 *
 * 执行时机:main() 中监听端口启动之前,在独立的 JS 运行时里执行一次。
 *          进程存活期间一直驻留,收到的"函数调用"请求由它串行处理。
 *
 * 与其他脚本的差异:
 *   - 不注入 HTTP / HTTP.send / ws(它不是请求脚本);
 *   - 文件 / SQL 访问权限由 base_msg.js_global_script 配置:
 *       字符串写法 = 只有脚本路径,沿用旧版本行为(完全文件 / SQL 权限);
 *       对象写法 = 与 roter 处理器一致,按 js_read_rule / js_write_rule /
 *                  js_sql_read_rule / js_sql_write_rule / js_full_access 授予;
 *       对象写法示例:
 *         "js_global_script": {
 *             "js_path": "examples/global.js",
 *             "js_read_rule": "data",
 *             "js_write_rule": "data",
 *             "js_sql_read_rule": "data/app.db",
 *             "js_sql_write_rule": "data/app.db",
 *             "js_full_access": false
 *         }
 *   - 同一次运行时里定义的函数挂到 globalThis 上,供网页脚本调用。
 *
 * 网页脚本用法(同步阻塞,直到本次调用返回):
 *   Global.call("add", [1, 2])        -> 3
 *   Global.call("echo", [{ a: 1 }])   -> { a: 1 }
 *   Global.call("now")                -> 时间戳(毫秒)
 *
 * 约定:
 *   - 参数与返回值都走 JSON 往返,不能传函数 / undefined / 循环引用;
 *   - 找不到函数时 Global.call 抛异常;
 *   - 函数抛异常时调用方收到异常(错误信息带堆栈)。
 */

// 纯计算
globalThis.add = function (a, b) {
    return Number(a) + Number(b);
};

// 回显任意 JSON 值
globalThis.echo = function (value) {
    return value;
};

// 当前时间
globalThis.now = function () {
    return Date.now();
};

// 维护内存计数器(全局脚本是常驻运行时,变量会跨调用保留)
var counter_value = 0;

globalThis.counter = function () {
    counter_value += 1;
    return counter_value;
};

console.log("global script ready");
