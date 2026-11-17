// 业务脚本:没有任何文件权限,但可以 Global.call 进全局脚本。
// Global.call 返回后必须恢复本脚本的权限上下文(不能继承全局脚本的 full access)。
const res = HTTP.send;
const out = {};
out.canReadBefore = File.canRead();
out.canWriteBefore = File.canWrite();
try {
  out.call = Global.call("ping");
} catch (e) {
  out.callError = e.name + ": " + e.message;
}
out.canReadAfter = File.canRead();
try {
  out.readAfter = File.readText("data/small.txt");
} catch (e) {
  out.readAfter = "denied:" + e.name;
}
res.json(out);
res.send();
