// 请求安全检测脚本(字符串写法 = 没有任何文件 / SQL 权限)
// 返回 false / 数字 / 对象都能控制拦截行为
function check(req) {
  const path = req.path;
  if (path === "/forbidden") {
    return { allow: false, status: 403, message: "blocked by policy", headers: { "X-Blocked": "1" } };
  }
  if (path === "/drop") {
    return -1; // 不回任何响应,直接断开
  }
  if (path === "/teapot") {
    return 418;
  }
  return true;
}
