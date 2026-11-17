# 参与贡献

感谢你愿意改进 Hhttp。这个项目很小,下面几条约定的目的只是让改动容易 review、容易回归。

## 开发环境

- C++17 编译器(GCC 11+ / Clang / MSVC)与 CMake ≥ 3.16;
- Boost(头文件)、OpenSSL 3.x、QuickJS、SQLite3,获取方式见
  [用户手册 · 依赖与版本](docs/用户手册.md#132-依赖与版本);
- 回归测试使用 PowerShell(Windows PowerShell 5.1 或 PowerShell 7)。

## 构建与测试

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

改完代码后请至少跑完三套回归:

```powershell
powershell -ExecutionPolicy Bypass -File tests\run-tests.ps1
powershell -ExecutionPolicy Bypass -File tests\run-routing-tests.ps1
powershell -ExecutionPolicy Bypass -File tests\run-tls-tests.ps1
```

三套脚本各自拉起服务、退出码为失败条数(0 表示全部通过)。
修改协议行为、权限模型或解析逻辑时,请同时补充对应的断言:
新增用例写在 `tests/run-tests.ps1`(HTTP / WS / 脚本 / 安全)、`tests/run-routing-tests.ps1`(路由)、
`tests/run-tls-tests.ps1`(TLS),测试脚本放在 `tests/scripts/`。

## 代码风格

- C++:4 空格缩进;类型用 `PascalCase`,函数 / 变量用 `snake_case`,成员变量带尾下划线;
  注释用中文,公开接口用 `/* @brief ... */` 风格。
- 脚本(JS):4 空格缩进;QuickJS 支持的语法范围内书写(尽量不用需要 Babel 的新语法)。
- 文档:中文,标点用全角;命令与代码片段放在代码块里。
- 不要新增第三方依赖;确有必要时请先开 issue 讨论,并在 README 的第三方组件表里登记许可证。

## 提交 PR

1. 从对应版本拉分支,一个 PR 只做一件事;
2. 描述里写清楚:**改了什么、为什么改、怎么验证**(贴回归输出更好);
3. 涉及协议 / 配置 / 权限的改动,请同步更新 `docs/用户手册.md` 对应章节;
4. 不要提交 `build/`、`LOG/`、本地 `config.json`、私钥或真实证书;
5. 安全相关的问题不要开公开 PR,请按 [SECURITY.md](SECURITY.md) 的方式报告。

## 目录速查

| 路径 | 放什么 |
| --- | --- |
| `src/` | 服务器源码(C++17) |
| `third_party/` | 仓库自带的第三方单头文件 |
| `scripts/` | 默认脚本目录(最小示例 + 全局 / 安全脚本示例) |
| `tests/` | 回归脚本与测试固件 |
| `docs/` | 用户手册 |
