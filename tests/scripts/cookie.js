// Cookie 读写
const req = HTTP.get;
const res = HTTP.send;
const c = new Cookie("sid", req.query().v || "v1");
c.path = "/";
c.httpOnly = true;
res.cookie(c);
res.set = undefined;
res.json({ read: req.cookie("sid"), all: req.cookies() });
res.send();
