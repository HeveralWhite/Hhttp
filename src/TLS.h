#ifndef TLS_H
#define TLS_H

#include <boost/asio/ssl/context.hpp>

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

/*
 *@brief 基于 OpenSSL 的 TLS 服务端实现
 *@note  本模块只负责"服务端 TLS 上下文"：证书加载、协议版本、按 SNI 选证书。
 *       真正的握手/加解密由 Boost.Asio 的 asio::ssl::stream 在 TCP::Base_Link
 *       内部完成（见 TCP.cpp 的 start_tls），因此上层（HTTP / WebSocket）依旧
 *       无需关心 TLS。
 *
 *       证书来源支持两种：
 *         - PFX/P12 文件（pfx_path + pfx_password）：与旧配置完全兼容；
 *         - PEM 证书链 + 私钥（cert_file + key_file）：Linux/macOS 上更常见。
 *       一个 HTTPS 端口可以配置多张证书：握手时按 ClientHello 的 SNI 域名
 *       挑选证书覆盖该域名的第一张（列表里的第一张是默认证书）。
 */
namespace TLS
{
/*
 *@struct Cert_source
 *@brief 一张服务端证书的来源
 */
struct Cert_source
{
    /* ---- 来源一:PFX/P12 文件(便于随程序分发) ---- */
    std::string pfx_path;     ///< PFX/P12 文件路径,非空时优先使用
    std::string pfx_password; ///< PFX 密码(无密码留空)

    /* ---- 来源二:PEM 证书链 + 私钥(Linux/macOS 常见) ---- */
    std::string cert_file; ///< PEM 证书(可含中间证书链)
    std::string key_file;  ///< PEM 私钥(PKCS#8 或传统 RSA/EC 格式)

    /*
     *@brief 是否配置了可用的证书来源
     */
    bool configured() const noexcept
    {
        return !pfx_path.empty() || (!cert_file.empty() && !key_file.empty());
    }
};

/*
 *@struct Server_config
 *@brief 服务端 TLS 配置(证书来源 + 协议选项)
 *@note  certs 非空时按"多证书 + SNI"工作;为空时退回下面的单证书字段
 */
struct Server_config
{
    /*
     *@brief 证书列表(第一张为默认证书;按 SNI 域名自动选择)
     */
    std::vector<Cert_source> certs;

    /* ---- 单证书写法(兼容旧代码) ---- */
    std::string pfx_path;     ///< PFX/P12 文件路径
    std::string pfx_password; ///< PFX 密码(无密码留空)
    std::string cert_file;    ///< PEM 证书链
    std::string key_file;     ///< PEM 私钥

    /* ---- 协议选项 ---- */
    bool enable_tls12 = true; ///< 允许 TLS 1.2
    bool enable_tls13 = true; ///< 允许 TLS 1.3(系统/OpenSSL 不支持时自动忽略)
};

class Context;

/*
 *@brief 当前平台是否支持 TLS(编译时是否带 OpenSSL)
 */
bool available() noexcept;

/*
 *@brief 创建服务端 TLS 上下文(加载证书)
 *@param cfg   配置
 *@param error 失败时写入错误原因
 *@return 成功返回上下文;失败返回 nullptr
 *@note  返回的上下文可被多条连接共享
 */
std::shared_ptr<Context> make_server_context(const Server_config &cfg, std::string &error);

/*
 *@class Context
 *@brief 服务端 TLS 上下文(OpenSSL SSL_CTX 集合 + SNI 选择)
 */
class Context
{
public:
    ~Context();
    Context(const Context &) = delete;
    Context &operator=(const Context &) = delete;

    /*
     *@brief 已加载证书的数量
     */
    std::size_t certificate_count() const noexcept;

    /*
     *@brief 已加载的证书里是否有能覆盖 host 的一张
     *@param host 域名:大小写不敏感,可带端口;支持 "*.example.com" 形式
     *@return true 表示有证书的 CN / SAN DNS 名能匹配该域名
     *@note  用于启动时检查"路由里出现的域名是否都有对应证书"
     */
    bool covers_host(const std::string &host) const;

    /*
     *@brief 默认（第一张证书）的 OpenSSL 上下文
     *@note  供 TCP::Base_Link 发起握手时使用;SNI 选证书在 TLS 层内部完成
     */
    boost::asio::ssl::context &native() noexcept;
    const boost::asio::ssl::context &native() const noexcept;

private:
    friend std::shared_ptr<Context> make_server_context(const Server_config &, std::string &);

    struct Impl;
    explicit Context(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> impl_;
};

} // namespace TLS

#endif // TLS_H
