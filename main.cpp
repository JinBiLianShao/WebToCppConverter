/**
 * @file main.cpp
 * @brief WebToCppConverter v2.0 - 静态网页资源 -> C++ 内嵌头文件转换器
 *
 * 把一个 web 目录（HTML/CSS/JS/图片等）转成单个自包含的 C++ 源文件：
 * 所有资源 base64 编码，按路由注册到 httplib::Server，页面编进二进制，
 * 目标板无需部署静态文件目录。
 *
 * v2.0 相对 v1.x 的改进：
 *  - 生成代码包进 webcontent 命名空间 + 解码器改名 decode_payload，
 *    避免与宿主工程（如 liblsx Crypto::base64Decode）符号冲突
 *  - 别名路由完整生成：/xxx.html 与 /xxx 同时注册
 *  - 每个资源带 MD5 指纹注释，--check 模式校验输出与 www/ 一致
 *  - MIME 表支持 --mime ext=type 扩展
 *  - 支持 --namespace / --fname 自定义命名空间与函数名
 *  - 严格模式：路由冲突直接报错退出
 *
 * @author 连思鑫（jinbilianshao）
 * @date 2026-11-11
 * @version 2.0.0
 */
#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unordered_map>
#include <vector>

struct WebFileInfo {
    std::string route;
    std::string full_path;
    std::string mime;
    std::string md5_hex;
    std::size_t size = 0;
};

// ---------------- Base64 ----------------

static std::string base64_encode(const std::string& in)
{
    static const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(table[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

// ---------------- MD5（RFC 1321，内容指纹与 --check 校验） ----------------

namespace md5impl {
inline std::uint32_t rotl(std::uint32_t x, unsigned c) { return (x << c) | (x >> (32 - c)); }
inline constexpr std::uint32_t K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391 };
inline constexpr unsigned S[4][16] = {
    {7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22},
    {5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20},
    {4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23},
    {6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21} };
} // namespace md5impl

class MD5 {
public:
    MD5() { a_=0x67452301; b_=0xefcdab89; c_=0x98badcfe; d_=0x10325476; total_=0; buf_len_=0; }
    void update(const std::uint8_t* d, std::size_t n) {
        total_ += n;
        while (n > 0) {
            std::size_t take = std::min(n, static_cast<std::size_t>(64 - buf_len_));
            std::memcpy(buf_ + buf_len_, d, take);
            buf_len_ += take; d += take; n -= take;
            if (buf_len_ == 64) { transform(buf_); buf_len_ = 0; }
        }
    }
    std::array<std::uint8_t, 16> final() {
        std::uint64_t bits = total_ * 8;
        std::uint8_t pad = 0x80;
        update(&pad, 1);
        std::uint8_t z = 0;
        while (buf_len_ != 56) update(&z, 1);
        std::uint8_t len[8];
        for (int i = 0; i < 8; ++i) len[i] = static_cast<std::uint8_t>(bits >> (i * 8));
        update(len, 8);
        std::array<std::uint8_t, 16> out{};
        for (int i = 0; i < 4; ++i) {
            out[i*4]   = static_cast<std::uint8_t>(a_);
            out[i*4+1] = static_cast<std::uint8_t>(a_ >> 8);
            out[i*4+2] = static_cast<std::uint8_t>(a_ >> 16);
            out[i*4+3] = static_cast<std::uint8_t>(a_ >> 24);
        }
        return out;
    }
private:
    void transform(const std::uint8_t block[64]) {
        std::uint32_t m[16];
        for (int i = 0; i < 16; ++i)
            m[i] = static_cast<std::uint32_t>(block[i*4]) |
                   (static_cast<std::uint32_t>(block[i*4+1]) << 8) |
                   (static_cast<std::uint32_t>(block[i*4+2]) << 16) |
                   (static_cast<std::uint32_t>(block[i*4+3]) << 24);
        std::uint32_t a = a_, b = b_, c = c_, d = d_;
        for (int i = 0; i < 64; ++i) {
            std::uint32_t f, g;
            if (i < 16)      { f = (b & c) | (~b & d); g = i; }
            else if (i < 32) { f = (d & b) | (~d & c); g = (5*i + 1) % 16; }
            else if (i < 48) { f = b ^ c ^ d;          g = (3*i + 5) % 16; }
            else             { f = c ^ (b | ~d);       g = (7*i) % 16; }
            f += a + md5impl::K[i] + m[g];
            a = d; d = c; c = b;
            b += md5impl::rotl(f, md5impl::S[i % 4][i / 16]);
        }
        a_ += a; b_ += b; c_ += c; d_ += d;
    }
    std::uint32_t a_, b_, c_, d_;
    std::uint64_t total_;
    std::uint8_t buf_[64];
    std::size_t buf_len_;
};

static std::string md5_hex(const std::string& data)
{
    MD5 m;
    m.update(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
    auto d = m.final();
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (auto b : d) { out.push_back(hex[b >> 4]); out.push_back(hex[b & 0x0F]); }
    return out;
}

// ---------------- MIME ----------------

static std::unordered_map<std::string, std::string> build_mime_map(
        const std::vector<std::string>& extra)
{
    std::unordered_map<std::string, std::string> m = {
        {".html", "text/html"}, {".htm", "text/html"},
        {".css", "text/css"}, {".js", "application/javascript"},
        {".json", "application/json"}, {".svg", "image/svg+xml"},
        {".png", "image/png"}, {".jpg", "image/jpeg"}, {".jpeg", "image/jpeg"},
        {".gif", "image/gif"}, {".webp", "image/webp"}, {".ico", "image/x-icon"},
        {".txt", "text/plain"}, {".xml", "application/xml"},
        {".woff", "font/woff"}, {".woff2", "font/woff2"}, {".ttf", "font/ttf"},
        {".mp3", "audio/mpeg"}, {".wav", "audio/wav"}, {".mp4", "video/mp4"},
        {".gz", "application/gzip"}, {".bin", "application/octet-stream"}
    };
    for (const auto& kv : extra) {
        std::size_t eq = kv.find('=');
        if (eq == std::string::npos) continue;
        std::string ext = kv.substr(0, eq);
        std::string type = kv.substr(eq + 1);
        if (!ext.empty() && ext[0] != '.') ext = "." + ext;
        if (!ext.empty() && !type.empty()) {
            std::string e = ext;
            std::transform(e.begin(), e.end(), e.begin(), ::tolower);
            m[e] = type;
        }
    }
    return m;
}

static std::string mime_type(const std::string& path,
                             const std::unordered_map<std::string, std::string>& mimes)
{
    auto dot = path.find_last_of('.');
    if (dot == std::string::npos) return "application/octet-stream";
    std::string ext = path.substr(dot);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    auto it = mimes.find(ext);
    return it == mimes.end() ? "application/octet-stream" : it->second;
}

// ---------------- 目录递归收集 ----------------

static void collect_files(std::vector<WebFileInfo>& out,
                          const std::string& base, const std::string& rel,
                          const std::unordered_map<std::string, std::string>& mimes)
{
    std::string dir = rel.empty() ? base : base + "/" + rel;
    DIR* d = opendir(dir.c_str());
    if (!d) return;
    struct dirent* e;
    while ((e = readdir(d))) {
        std::string name = e->d_name;
        if (name == "." || name == "..") continue;
        std::string full = dir + "/" + name;
        std::string rp = rel.empty() ? name : rel + "/" + name;
        struct stat st;
        if (stat(full.c_str(), &st) == -1) continue;
        if (S_ISDIR(st.st_mode)) { collect_files(out, base, rp, mimes); continue; }
        if (!S_ISREG(st.st_mode)) continue;
        WebFileInfo info;
        info.route = "/" + rp;
        info.full_path = full;
        info.mime = mime_type(full, mimes);
        std::ifstream f(full, std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        info.size = content.size();
        info.md5_hex = md5_hex(content);
        out.push_back(std::move(info));
    }
    closedir(d);
    std::sort(out.begin(), out.end(), [](const WebFileInfo& a, const WebFileInfo& b)
              { return a.route < b.route; });
}

// ---------------- 路由展开 ----------------

static std::vector<std::string> routesFor(const WebFileInfo& f, bool alias)
{
    std::vector<std::string> r{f.route};
    if (alias && f.route.size() > 5 && f.route.substr(f.route.size() - 5) == ".html")
        r.push_back(f.route.substr(0, f.route.size() - 5));
    return r;
}

// ---------------- 生成器 ----------------

static std::string generate(const std::vector<WebFileInfo>& files,
                            const std::string& ns, const std::string& fname,
                            bool alias)
{
    std::ostringstream o;
    o << "//\n";
    o << "// 自动生成：WebToCppConverter v2.0 —— 静态资源 base64 内嵌\n";
    o << "// 由 WebToCppConverter 生成，请勿手工修改；web/ 目录更新后重新运行。\n";
    o << "//\n";
    o << "// 用法：在宿主工程里调用 " << ns << "::" << fname << "(svr)\n";
    o << "//       解码器为 " << ns << "::decode_payload（与宿主工程的 base64 实现互不冲突）\n";
    o << "//\n";
    o << "#include \"httplib.h\"\n";
    o << "#include <string>\n";
    o << "#include <vector>\n";
    o << "\n";
    o << "namespace " << ns << " {\n";
    o << "\n";
    o << "// 内嵌资源 base64 解码（与宿主工程的解码器相互独立）\n";
    o << "static std::string decode_payload(const std::string& in) {\n";
    o << "    static const char* kTable = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\";\n";
    o << "    std::string out;\n";
    o << "    std::vector<int> T(256, -1);\n";
    o << "    for (int i = 0; i < 64; ++i) T[static_cast<unsigned char>(kTable[i])] = i;\n";
    o << "    int val = 0, valb = -8;\n";
    o << "    for (unsigned char c : in) {\n";
    o << "        if (T[c] == -1) break;\n";
    o << "        val = (val << 6) + T[c];\n";
    o << "        valb += 6;\n";
    o << "        if (valb >= 0) {\n";
    o << "            out.push_back(static_cast<char>((val >> valb) & 0xFF));\n";
    o << "            valb -= 8;\n";
    o << "        }\n";
    o << "    }\n";
    o << "    return out;\n";
    o << "}\n";
    o << "\n";
    o << "void " << fname << "(httplib::Server& svr) {\n";

    for (const auto& f : files)
    {
        std::ifstream in(f.full_path, std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        std::string b64 = base64_encode(content);

        o << "\n";
        o << "  // " << f.route << "  (" << f.mime << ", " << f.size << " bytes, md5=" << f.md5_hex << ")\n";
        for (const auto& route : routesFor(f, alias))
        {
            o << "  svr.Get(R\"(" << route << ")\", [](const httplib::Request&, httplib::Response& res) {\n";
            o << "    res.set_content(decode_payload(R\"B64(" << b64 << ")B64\"), \"" << f.mime << "\");\n";
            o << "  });\n";
        }
    }
    o << "}\n\n";
    o << "} // namespace " << ns << "\n";
    return o.str();
}

// ---------------- 主流程 ----------------

int main(int argc, char* argv[])
{
    std::string web_dir, out_file, ns = "webcontent", fname = "setup_static_routes";
    bool alias = true, check = false;
    std::vector<std::string> extra_mime;

    std::vector<std::string> args(argv + 1, argv + argc);
    for (std::size_t i = 0; i < args.size(); ++i)
    {
        const std::string& a = args[i];
        if (a == "--namespace" && i + 1 < args.size()) ns = args[++i];
        else if (a == "--fname" && i + 1 < args.size()) fname = args[++i];
        else if (a == "--mime" && i + 1 < args.size()) extra_mime.push_back(args[++i]);
        else if (a == "--check") check = true;
        else if (a == "--no-alias") alias = false;
        else if (a == "-h" || a == "--help") {
            std::cout << "用法: WebToCppConverter <web目录> <输出cpp文件> [选项]\n"
                      << "  --namespace NAME   命名空间（默认 webcontent）\n"
                      << "  --fname NAME       路由注册函数名（默认 setup_static_routes）\n"
                      << "  --mime ext=type    追加 MIME 映射（可多次）\n"
                      << "  --check            校验输出与 web 目录一致\n"
                      << "  --no-alias         不生成无扩展名别名路由\n";
            return 0;
        }
        else if (web_dir.empty()) web_dir = a;
        else if (out_file.empty()) out_file = a;
    }
    if (web_dir.empty() || out_file.empty()) {
        std::cerr << "用法: " << argv[0] << " <web目录> <输出cpp文件> [选项]\n";
        return 1;
    }

    auto mimes = build_mime_map(extra_mime);
    std::vector<WebFileInfo> files;
    collect_files(files, web_dir, "", mimes);
    if (files.empty()) {
        std::cerr << "警告: "" << web_dir << "" 中未找到任何文件\n";
        return 1;
    }

    // 路由冲突检查（严格模式）
    {
        std::map<std::string, std::string> seen;
        for (const auto& f : files)
            for (const auto& r : routesFor(f, alias))
            {
                auto it = seen.find(r);
                if (it != seen.end() && it->second != f.full_path)
                {
                    std::cerr << "错误: 路由冲突 " << r << " -> " << it->second
                              << " 与 " << f.full_path << "\n";
                    return 1;
                }
                seen[r] = f.full_path;
            }
    }

    std::string content = generate(files, ns, fname, alias);

    if (check)
    {
        std::ifstream f(out_file, std::ios::binary);
        if (!f) { std::cerr << "CHECK FAILED: 输出文件不存在\n"; return 1; }
        std::string cur((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        if (cur == content) { std::cout << "CHECK OK: 输出与 web 目录一致\n"; return 0; }
        std::cerr << "CHECK FAILED: 输出与 web 目录不一致（重新运行转换器）\n";
        return 1;
    }

    std::ofstream f(out_file, std::ios::binary | std::ios::trunc);
    if (!f) { std::cerr << "错误: 无法写入 " << out_file << "\n"; return 1; }
    f << content;
    f.close();
    std::cout << "生成成功: " << out_file << " (" << files.size() << " 个资源, "
              << content.size() << " 字节)\n";
    for (const auto& fi : files)
        std::cout << "  " << fi.route << "  " << fi.mime << "  " << fi.size
                  << "B  md5=" << fi.md5_hex << "\n";
    return 0;
}
