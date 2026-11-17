// SQLite 读写 + 权限边界
const res = HTTP.send;
const out = {};
if (typeof Sqlite === "undefined") {
  out.noSqlite = true;
} else {
  const db = Sqlite.open("data/test.db");
  db.exec("CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)");
  db.run("INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)", "k1", "v1");
  out.rows = db.query("SELECT k, v FROM kv ORDER BY k");
  out.columns = db.query("SELECT k, v FROM kv").columns;
  db.close();
  out.denied = false;
  try {
    Sqlite.open("data/other.db");
    out.denied = "opened";
  } catch (e) {
    out.denied = e.name;
  }
}
res.json(out);
res.send();
