// 文件接口 + 权限边界
const req = HTTP.get;
const res = HTTP.send;
const name = req.query().name || "data/small.txt";
const out = {};
try {
  out.text = File.readText(name);
} catch (e) {
  out.error = e.name + ": " + e.message;
}
try {
  out.exists = File.exists(name);
} catch (e) {
  out.existsError = e.name;
}
res.json(out);
res.send();
