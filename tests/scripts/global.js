// 全局数据脚本:拥有完全文件 / SQL 权限(由 js_full_access 授予)
// 业务脚本通过 Global.call 调用这里的函数,用来验证"权限上下文不会被带回去"
function ping() {
  const canSeeFile = File.exists("data/small.txt"); // full access:应能访问
  store.set("ping", { count: 1 });
  return { canSeeFile: canSeeFile, stored: store.has("ping") };
}
