// 响应头注入探针:把查询参数原样写进响应头(名称与值)与状态短语
const req = HTTP.get;
const res = HTTP.send;
const q = req.query();
res.header(q.h || "X-Echo", q.v || "ok");
res.status(Number(q.code || 200), q.reason || undefined);
res.text("ok");
res.send();
