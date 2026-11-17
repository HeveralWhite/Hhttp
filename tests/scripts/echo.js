// 回显请求信息,便于验证 HTTP 解析层的行为(含 TLS 连接信息)
const req = HTTP.get;
const res = HTTP.send;
const out = {
  method: req.method(),
  url: req.url(),
  rawUrl: req.rawUrl(),
  version: req.version(),
  query: req.query(),
  headerHost: req.header("host"),
  cookie: req.cookie("a"),
  body: req.body(),
  bodyLen: req.body().length,
  peer: req.peer(),
  scheme: req.scheme(),
  https: req.isHttps(),
  tls: req.tlsProtocol(),
};
res.json(out);
res.send();
