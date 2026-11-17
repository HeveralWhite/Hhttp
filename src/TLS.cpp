#include "TLS.h"

#include <boost/asio/ssl.hpp>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace TLS
{
namespace ssl = boost::asio::ssl;

namespace
{

/*
 *@brief 把当前线程的 OpenSSL 错误队列拼成可读字符串
 */
std::string Openssl_error()
{
    std::string text;
    unsigned long code = 0;
    while ((code = ERR_get_error()) != 0)
    {
        char buffer[256] = {0};
        ERR_error_string_n(code, buffer, sizeof(buffer));
        if (!text.empty())
            text += "; ";
        text += buffer;
    }
    return text.empty() ? std::string("unknown OpenSSL error") : text;
}

/*
 *@brief 尽力加载 legacy provider,让老式 PFX(RC2 / RC4 / DES 加密)也能解析
 *@note  OpenSSL 3.x 默认只加载 default provider,RC2/RC4/DES 被移到了 legacy
 *       provider。静态构建里如果没有把 legacy 模块一起编进来,这里会失败,
 *       忽略即可(不影响 TLS 本身);此时老式 PFX 会在 Load_from_pfx 里给出
 *       明确的"算法不支持"提示。
 *@note  注意:一旦显式加载了任何 provider,OpenSSL 就**不再自动加载 default
 *       provider**;所以这里必须把 default 也显式加载,否则 SSL_CTX_new 会失败。
 */
void Ensure_providers()
{
    static std::once_flag once;
    std::call_once(once, []
    {
        // 失败时 OpenSSL 会往错误队列里塞 DSO/provider 错误,清掉避免污染后续诊断
        ERR_clear_error();

        if (OSSL_PROVIDER_load(nullptr, "default") == nullptr)
            ERR_clear_error();

        if (OSSL_PROVIDER_load(nullptr, "legacy") == nullptr)
            ERR_clear_error();
    });
}

/*
 *@brief 域名归一化:转小写、去掉端口、去掉结尾的点
 */
std::string Normalize_host(const std::string &host)
{
    std::string text = host;

    const std::size_t begin = text.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos)
        return std::string();
    const std::size_t end = text.find_last_not_of(" \t\r\n");
    text = text.substr(begin, end - begin + 1);

    for (char &ch : text)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));

    // 去掉端口:IPv6 的 [::1]:443 保留方括号形式(证书不会匹配 IP)
    if (!text.empty() && text.front() == '[')
    {
        const std::size_t close = text.find(']');
        if (close != std::string::npos && close + 1 < text.size() &&
                text[close + 1] == ':')
            text.erase(close + 1);
    }
    else
    {
        const std::size_t colon = text.find(':');
        if (colon != std::string::npos)
            text.erase(colon);
    }

    while (!text.empty() && text.back() == '.')
        text.pop_back();
    return text;
}

/*
 *@brief 证书是否覆盖某个域名(检查 SAN / CN,支持单级通配)
 *@param host 已归一化的域名
 */
bool Cert_covers(X509 *cert, const std::string &host)
{
    if (cert == nullptr || host.empty())
        return false;
    return X509_check_host(cert, host.c_str(), host.size(), 0, nullptr) == 1;
}

/*
 *@brief 读整个文件到内存
 */
bool Read_whole_file(const std::string &path, std::string &out)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        return false;
    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    if (size < 0)
        return false;
    in.seekg(0, std::ios::beg);
    out.resize(static_cast<std::size_t>(size));
    if (size > 0)
        in.read(out.data(), size);
    return static_cast<bool>(in) || in.eof();
}

/*
 *@brief 给上下文设置协议版本与安全选项
 */
void Configure_protocols(ssl::context &context, const Server_config &cfg)
{
    SSL_CTX *native = context.native_handle();

    long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
#ifdef SSL_OP_NO_RENEGOTIATION
    options |= SSL_OP_NO_RENEGOTIATION;
#endif
    SSL_CTX_set_options(native, options);

    // 协议范围:默认 1.2 ~ 1.3;只允许其中一个时收窄到那一个
    int min_version = TLS1_2_VERSION;
    int max_version = TLS1_3_VERSION;

    if (!cfg.enable_tls12 && cfg.enable_tls13)
        min_version = TLS1_3_VERSION;
    else if (cfg.enable_tls12 && !cfg.enable_tls13)
        max_version = TLS1_2_VERSION;
    else if (!cfg.enable_tls12 && !cfg.enable_tls13)
        max_version = TLS1_2_VERSION; // 两个都关:退回 1.2,避免配出"无协议可用"

    SSL_CTX_set_min_proto_version(native, min_version);
    SSL_CTX_set_max_proto_version(native, max_version);

    // 服务端优先选择自己的套件顺序(浏览器兼容性更好)
    SSL_CTX_set_options(native, SSL_OP_CIPHER_SERVER_PREFERENCE);
}

/*
 *@brief 从 PFX/P12 导入证书与私钥
 */
bool Load_from_pfx(ssl::context &context, const Cert_source &source, std::string &error)
{
    std::string data;
    if (!Read_whole_file(source.pfx_path, data) || data.empty())
    {
        error = "cannot read PFX file: " + source.pfx_path;
        return false;
    }

    const unsigned char *cursor =
        reinterpret_cast<const unsigned char *>(data.data());
    PKCS12 *p12 = d2i_PKCS12(nullptr, &cursor, static_cast<long>(data.size()));
    if (p12 == nullptr)
    {
        error = "cannot parse PFX file: " + Openssl_error();
        return false;
    }

    EVP_PKEY *key = nullptr;
    X509 *cert = nullptr;
    STACK_OF(X509) *chain = nullptr;
    const char *password = source.pfx_password.empty()
                           ? "" : source.pfx_password.c_str();

    // 老式 PFX 用 RC2 / RC4 / DES 加密,OpenSSL 3 默认 provider 里没有这些算法
    Ensure_providers();
    ERR_clear_error();

    const int parsed = PKCS12_parse(p12, password, &key, &cert, &chain);
    PKCS12_free(p12);
    if (parsed != 1 || key == nullptr || cert == nullptr)
    {
        const std::string detail = Openssl_error();

        // 区分两种失败:密码错(mac verify)和算法不支持(legacy provider 缺失)
        const bool unsupported =
            detail.find("unsupported") != std::string::npos ||
            detail.find("unknown algorithm") != std::string::npos ||
            detail.find("provider") != std::string::npos;
        const bool bad_password =
            detail.find("mac verify") != std::string::npos ||
            detail.find("invalid password") != std::string::npos;

        if (unsupported)
        {
            error = "cannot decrypt PFX: the file was exported with a legacy encryption "
                    "algorithm (RC2 / RC4 / DES) that OpenSSL 3 does not enable by default; "
                    "re-export it with AES or 3DES (Export-PfxCertificate "
                    "-CryptoAlgorithmOption AES256_SHA256), or use cert_file/key_file "
                    "instead. " + detail;
        }
        else if (bad_password)
        {
            error = "cannot decrypt PFX: wrong password (or the file uses a legacy "
                    "algorithm). " + detail;
        }
        else
        {
            error = "cannot decrypt PFX: " + detail;
        }
        if (key)
            EVP_PKEY_free(key);
        if (cert)
            X509_free(cert);
        if (chain)
            sk_X509_pop_free(chain, X509_free);
        return false;
    }

    SSL_CTX *native = context.native_handle();
    bool ok = SSL_CTX_use_certificate(native, cert) == 1 &&
              SSL_CTX_use_PrivateKey(native, key) == 1;

    if (ok && chain != nullptr)
    {
        // add_extra_chain_cert 接管所有权,所以传副本
        for (int i = 0; i < sk_X509_num(chain); ++i)
        {
            X509 *item = sk_X509_value(chain, i);
            if (item != nullptr)
                SSL_CTX_add_extra_chain_cert(native, X509_dup(item));
        }
    }

    if (ok && SSL_CTX_check_private_key(native) != 1)
        ok = false;

    if (!ok && error.empty())
        error = "certificate/private key rejected: " + Openssl_error();

    X509_free(cert);
    EVP_PKEY_free(key);
    if (chain)
        sk_X509_pop_free(chain, X509_free);
    return ok;
}

/*
 *@brief 从 PEM 证书链 + 私钥加载
 */
bool Load_from_pem(ssl::context &context, const Cert_source &source,
                   std::string &error)
{
    SSL_CTX *native = context.native_handle();

    if (SSL_CTX_use_certificate_chain_file(native, source.cert_file.c_str()) != 1)
    {
        error = "cannot load certificate chain (" + source.cert_file +
                "): " + Openssl_error();
        return false;
    }
    if (SSL_CTX_use_PrivateKey_file(native, source.key_file.c_str(),
                                    SSL_FILETYPE_PEM) != 1)
    {
        error = "cannot load private key (" + source.key_file +
                "): " + Openssl_error();
        return false;
    }
    if (SSL_CTX_check_private_key(native) != 1)
    {
        error = "certificate and private key do not match: " + Openssl_error();
        return false;
    }
    return true;
}

/*
 *@brief 加载一张证书到上下文
 */
bool Load_cert(ssl::context &context, const Cert_source &source, std::string &error)
{
    if (!source.pfx_path.empty())
        return Load_from_pfx(context, source, error);
    if (!source.cert_file.empty() && !source.key_file.empty())
        return Load_from_pem(context, source, error);

    error = "no certificate configured (pfx_path or cert_file + key_file)";
    return false;
}
} // namespace

// ==================== Context::Impl ====================

struct Context::Impl
{
    /// 每张证书一个 SSL_CTX(第一个是默认证书);用 unique_ptr 是因为
    /// asiossl::context 不可拷贝,而 SNI 需要在多个上下文之间切换
    std::vector<std::unique_ptr<ssl::context>> contexts;
    /// 证书副本,仅用于启动时 covers_host 检查
    std::vector<X509 *> certs;

    ~Impl()
    {
        for (X509 *cert : certs)
            X509_free(cert);
    }

    /*
     *@brief ClientHello 的 SNI 回调:按域名切换到对应的 SSL_CTX
     *@note  这是 OpenSSL 官方的多证书模式:回调里调用 SSL_set_SSL_CTX,
     *       之后握手会用新上下文的证书/私钥
     */
    static int Sni_callback(SSL *ssl, int *alert, void *arg)
    {
        (void)alert;
        auto *impl = static_cast<Impl *>(arg);
        if (ssl == nullptr || impl == nullptr)
            return SSL_TLSEXT_ERR_NOACK;

        const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        if (name == nullptr || *name == '\0')
            return SSL_TLSEXT_ERR_NOACK; // 没有 SNI:用默认证书

        const std::string host = Normalize_host(name);
        if (host.empty())
            return SSL_TLSEXT_ERR_NOACK;

        for (std::size_t i = 0; i < impl->certs.size(); ++i)
        {
            if (Cert_covers(impl->certs[i], host))
            {
                SSL_set_SSL_CTX(ssl, impl->contexts[i]->native_handle());
                return SSL_TLSEXT_ERR_OK;
            }
        }
        return SSL_TLSEXT_ERR_NOACK; // 没有匹配的证书:用默认证书
    }
};

// ==================== Context ====================

Context::Context(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

Context::~Context() = default;

std::size_t Context::certificate_count() const noexcept
{
    return impl_ ? impl_->certs.size() : 0;
}

bool Context::covers_host(const std::string &host) const
{
    if (!impl_ || impl_->certs.empty())
        return false;

    std::string name = Normalize_host(host);
    if (name.empty())
        return false;

    // 路由键里的 "*.example.com" 用同级的具体域名去探测
    if (name.size() > 2 && name[0] == '*' && name[1] == '.')
        name = "hhttp-probe" + name.substr(1);

    for (X509 *cert : impl_->certs)
    {
        if (Cert_covers(cert, name))
            return true;
    }
    return false;
}

ssl::context &Context::native() noexcept
{
    return *impl_->contexts.front();
}

const ssl::context &Context::native() const noexcept
{
    return *impl_->contexts.front();
}

bool available() noexcept
{
    return true;
}

// ==================== 创建上下文 ====================

std::shared_ptr<Context> make_server_context(const Server_config &cfg,
        std::string &error)
{
    error.clear();

    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS |
                     OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    // 老式 PFX(RC2 / RC4 / DES)需要 legacy provider;模块不存在时会被忽略
    Ensure_providers();

    // ---- 1. 组装证书来源列表:优先多证书,否则退回单证书字段 ----
    std::vector<Cert_source> sources = cfg.certs;
    if (sources.empty())
    {
        Cert_source single;
        single.pfx_path = cfg.pfx_path;
        single.pfx_password = cfg.pfx_password;
        single.cert_file = cfg.cert_file;
        single.key_file = cfg.key_file;
        if (single.configured())
            sources.push_back(std::move(single));
    }
    if (sources.empty())
    {
        error = "no certificate configured (pfx_path or cert_file + key_file)";
        return nullptr;
    }

    // ---- 2. 每张证书一个上下文 ----
    auto impl = std::unique_ptr<Context::Impl>(new Context::Impl());
    for (std::size_t i = 0; i < sources.size(); ++i)
    {
        // Asio 在 SSL_CTX_new / set_options 失败时抛 boost::system::system_error,
        // 这里转成普通错误字符串,避免启动阶段直接 std::terminate
        std::unique_ptr<ssl::context> context;
        try
        {
            context.reset(new ssl::context(ssl::context::tls_server));
            Configure_protocols(*context, cfg);
        }
        catch (const std::exception &e)
        {
            error = "certificate #" + std::to_string(i + 1) + ": " + e.what();
            return nullptr;
        }

        std::string item_error;
        if (!Load_cert(*context, sources[i], item_error))
        {
            error = "certificate #" + std::to_string(i + 1) + ": " + item_error;
            return nullptr;
        }

        X509 *loaded = SSL_CTX_get0_certificate(context->native_handle());
        if (loaded != nullptr)
            impl->certs.push_back(X509_dup(loaded));

        impl->contexts.push_back(std::move(context));
    }

    if (impl->certs.empty())
    {
        error = "no usable certificate found";
        return nullptr;
    }

    // ---- 3. 注册 SNI 回调(每个上下文都要注册,arg 指向同一个 Impl)----
    for (auto &context : impl->contexts)
    {
        SSL_CTX_set_tlsext_servername_callback(context->native_handle(),
                                               &Context::Impl::Sni_callback);
        SSL_CTX_set_tlsext_servername_arg(context->native_handle(), impl.get());
    }

    return std::shared_ptr<Context>(new Context(std::move(impl)));
}

} // namespace TLS
