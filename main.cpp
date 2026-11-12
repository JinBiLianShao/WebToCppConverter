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
#include <unistd.h>
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

/// gzip 压缩（构建机调 gzip 命令；头尾保留，生成代码里按 raw deflate 解压）
static std::string gzip_compress(const std::string& in)
{
    std::string tmp_in = "/tmp/wtc_gz_in_" + std::to_string(getpid());
    std::string tmp_out = "/tmp/wtc_gz_out_" + std::to_string(getpid());
    {
        std::ofstream f(tmp_in, std::ios::binary);
        f.write(in.data(), static_cast<std::streamsize>(in.size()));
    }
    std::string cmd = "gzip -9 -c < " + tmp_in + " > " + tmp_out + " 2>/dev/null";
    int rc = std::system(cmd.c_str());
    std::string result;
    std::ifstream g(tmp_out, std::ios::binary);
    if (rc == 0 && g)
        result.assign((std::istreambuf_iterator<char>(g)), std::istreambuf_iterator<char>());
    g.close();
    std::remove(tmp_in.c_str());
    std::remove(tmp_out.c_str());
    if (result.size() < 18) return {};  // gzip 失败或输出异常
    return result;
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

// ---------------- tinfl DEFLATE 解压器（生成到头文件里） ----------------

namespace tinfl {

struct Decomp {
    const unsigned char* src;
    unsigned int srclen;
    unsigned int tag;
    unsigned int bitcount;
    unsigned char* dest;
    unsigned int destcap;
    unsigned int outpos;
};

struct HuffTree {
    unsigned short counts[16];
    unsigned short symbols[288];
};

static int decode_symbol(struct Decomp* d, const struct HuffTree* t) {
    int sum = 0, cur = 0, len = 0;
    do {
        cur = 2 * cur + ((d->tag >> d->bitcount) & 1);
        d->bitcount++;
        len++;
        sum += t->counts[len];
        cur -= t->counts[len];
    } while (cur >= 0 && len < 16);
    if (cur < 0 || len >= 16) return -1;
    return t->symbols[sum + cur];
}

static void build_tree(struct HuffTree* t, const unsigned char* lengths, int n) {
    for (int i = 0; i < 16; ++i) t->counts[i] = 0;
    for (int i = 0; i < n; ++i) t->counts[lengths[i]]++;
    t->counts[0] = 0;
    unsigned short offs[16];
    offs[0] = 0;
    for (int i = 1; i < 16; ++i) offs[i] = offs[i-1] + t->counts[i];
    for (int i = 0; i < n; ++i)
        if (lengths[i]) t->symbols[offs[lengths[i]]++] = i;
}

static unsigned int getbit(struct Decomp* d) {
    unsigned int bit = (d->tag >> (d->bitcount & 31)) & 1;
    if (++d->bitcount > 30) {
        unsigned int val = 0;
        for (int i = 0; i < 4 && d->srclen > 0; ++i) {
            val |= ((unsigned int)(*d->src++)) << (8 * i);
            --d->srclen;
        }
        d->tag = val;
        d->bitcount = 0;
    }
    return bit;
}

static unsigned int getbits(struct Decomp* d, int n) {
    unsigned int v = 0;
    for (int i = 0; i < n; ++i) v |= getbit(d) << i;
    return v;
}

static void buildFixedLit(struct HuffTree* t) {
    unsigned char lengths[288];
    for (int i = 0; i < 144; ++i) lengths[i] = 8;
    for (int i = 144; i < 256; ++i) lengths[i] = 9;
    for (int i = 256; i < 280; ++i) lengths[i] = 7;
    for (int i = 280; i < 288; ++i) lengths[i] = 8;
    build_tree(t, lengths, 288);
}

static void buildFixedDist(struct HuffTree* t) {
    unsigned char lengths[30];
    for (int i = 0; i < 30; ++i) lengths[i] = 5;
    build_tree(t, lengths, 30);
}

static const unsigned short lenBase[29] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
static const unsigned short lenExt[29] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
static const unsigned short distBase[30] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385};
static const unsigned short distExt[30] = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};

static unsigned int rawInflate(const unsigned char* src, unsigned int srclen,
                               unsigned char* dest, unsigned int destcap) {
    struct Decomp d = {src, srclen, 0, 0, dest, destcap, 0};
    for (int i = 0; i < 4 && d.srclen > 0; ++i) {
        d.tag |= ((unsigned int)(*d.src++)) << (8 * i);
        --d.srclen;
    }
    struct HuffTree litTree, distTree;
    int finalBlock = 0;
    while (!finalBlock) {
        finalBlock = (int)getbit(&d);
        unsigned int btype = (unsigned int)getbits(&d, 2);
        if (btype == 0) {
            while (d.bitcount % 8) getbit(&d);
            unsigned int lb = getbits(&d, 16);
            unsigned int hb = getbits(&d, 16);
            for (unsigned int i = 0; i < lb; ++i) {
                if (d.outpos >= destcap) return (unsigned int)-1;
                dest[d.outpos++] = (unsigned char)getbits(&d, 8);
            }
            for (unsigned int i = 0; i < hb; ++i) {
                if (d.outpos >= destcap) return (unsigned int)-1;
                dest[d.outpos++] = (unsigned char)getbits(&d, 8);
            }
        } else if (btype == 1 || btype == 2) {
            if (btype == 1) { buildFixedLit(&litTree); buildFixedDist(&distTree); }
            else {
                unsigned int hlit = getbits(&d, 5) + 257;
                unsigned int hdist = getbits(&d, 5) + 1;
                unsigned int hclen = getbits(&d, 4) + 4;
                const unsigned char order[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
                unsigned char clen[19] = {};
                for (unsigned int i = 0; i < hclen; ++i) clen[order[i]] = (unsigned char)getbits(&d, 3);
                struct HuffTree clTree;
                build_tree(&clTree, clen, 19);
                unsigned char lengths[288 + 30] = {};
                unsigned int idx = 0;
                while (idx < hlit + hdist) {
                    int sym = decode_symbol(&d, &clTree);
                    if (sym < 0) return (unsigned int)-1;
                    if (sym < 16) { lengths[idx++] = (unsigned char)sym; }
                    else {
                        int rep = 0; unsigned char val = 0;
                        if (sym == 16) { rep = 3 + (int)getbits(&d, 2); val = lengths[idx - 1]; }
                        else if (sym == 17) { rep = 3 + (int)getbits(&d, 3); val = 0; }
                        else { rep = 11 + (int)getbits(&d, 7); val = 0; }
                        for (int k = 0; k < rep && idx < hlit + hdist; ++k) lengths[idx++] = val;
                    }
                }
                build_tree(&litTree, lengths, hlit);
                build_tree(&distTree, lengths + hlit, hdist);
            }
            while (true) {
                int sym = decode_symbol(&d, &litTree);
                if (sym < 0) return (unsigned int)-1;
                if (sym < 256) {
                    if (d.outpos >= destcap) return (unsigned int)-1;
                    dest[d.outpos++] = (unsigned char)sym;
                } else if (sym == 256) break;
                else {
                    sym -= 257;
                    if (sym >= 29) return (unsigned int)-1;
                    unsigned int len = lenBase[sym] + getbits(&d, lenExt[sym]);
                    int dsym = decode_symbol(&d, &distTree);
                    if (dsym < 0 || dsym >= 30) return (unsigned int)-1;
                    unsigned int dist = distBase[dsym] + getbits(&d, distExt[dsym]);
                    if (dist > d.outpos) return (unsigned int)-1;
                    for (unsigned int i = 0; i < len; ++i) {
                        if (d.outpos >= destcap) return (unsigned int)-1;
                        dest[d.outpos] = dest[d.outpos - dist];
                        d.outpos++;
                    }
                }
            }
        } else return (unsigned int)-1;
        if (d.srclen == 0 && finalBlock) break;
    }
    return d.outpos;
}

} // namespace tinfl

// ---------------- 生成器 ----------------

static std::string generate(const std::vector<WebFileInfo>& files,
                            const std::string& ns, const std::string& fname,
                            bool alias, bool compress)
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
    if (compress) {
    // 嵌入 tinfl 解压器（自包含，不依赖 liblsx 或 zlib）
    o << "namespace tinfl {\n";
    o << "struct Decomp {\n";
    o << "    const unsigned char* src;\n";
    o << "    unsigned int srclen;\n";
    o << "    unsigned int tag;\n";
    o << "    unsigned int bitcount;\n";
    o << "    unsigned char* dest;\n";
    o << "    unsigned int destcap;\n";
    o << "    unsigned int outpos;\n";
    o << "};\n";
    o << "struct HuffTree {\n";
    o << "    unsigned short counts[16];\n";
    o << "    unsigned short symbols[288];\n";
    o << "};\n";
    o << "static unsigned int getbit(struct Decomp* d) {\n";
    o << "    if (d->bitcount == 0) {\n";
    o << "        unsigned int val = 0;\n";
    o << "        for (int i = 0; i < 4 && d->srclen > 0; ++i) {\n";
    o << "            val |= ((unsigned int)(*d->src++)) << (8 * i);\n";
    o << "            --d->srclen;\n";
    o << "        }\n";
    o << "        d->tag = val;\n";
    o << "        d->bitcount = 32;\n";
    o << "    }\n";
    o << "    unsigned int bit = d->tag & 1;\n";
    o << "    d->tag >>= 1;\n";
    o << "    d->bitcount--;\n";
    o << "    return bit;\n";
    o << "}\n";
    o << "static unsigned int getbits(struct Decomp* d, int n) {\n";
    o << "    unsigned int v = 0;\n";
    o << "    for (int i = 0; i < n; ++i) v |= getbit(d) << i;\n";
    o << "    return v;\n";
    o << "}\n";

    o << "static int decode_symbol(struct Decomp* d, const struct HuffTree* t) {\n";
    o << "    int sum = 0, cur = 0, len = 0;\n";
    o << "    do {\n";
    o << "        cur = 2 * cur + (int)getbit(d);\n";
    o << "        len++;\n";
    o << "        sum += t->counts[len];\n";
    o << "        cur -= t->counts[len];\n";
    o << "    } while (cur >= 0 && len < 16);\n";
    o << "    if (len >= 16) return -1;\n";
    o << "    return t->symbols[sum + cur];\n";
    o << "}\n";
    o << "static void build_tree(struct HuffTree* t, const unsigned char* lengths, int n) {\n";
    o << "    for (int i = 0; i < 16; ++i) t->counts[i] = 0;\n";
    o << "    for (int i = 0; i < n; ++i) t->counts[lengths[i]]++;\n";
    o << "    t->counts[0] = 0;\n";
    o << "    unsigned short offs[16];\n";
    o << "    offs[0] = 0;\n";
    o << "    for (int i = 1; i < 16; ++i) offs[i] = offs[i-1] + t->counts[i-1];\n";
    o << "    for (int i = 0; i < n; ++i)\n";
    o << "        if (lengths[i]) t->symbols[offs[lengths[i]]++] = i;\n";
    o << "}\n";
    o << "static void buildFixedLit(struct HuffTree* t) {\n";
    o << "    unsigned char lengths[288];\n";
    o << "    for (int i = 0; i < 144; ++i) lengths[i] = 8;\n";
    o << "    for (int i = 144; i < 256; ++i) lengths[i] = 9;\n";
    o << "    for (int i = 256; i < 280; ++i) lengths[i] = 7;\n";
    o << "    for (int i = 280; i < 288; ++i) lengths[i] = 8;\n";
    o << "    build_tree(t, lengths, 288);\n";
    o << "}\n";
    o << "static void buildFixedDist(struct HuffTree* t) {\n";
    o << "    unsigned char lengths[30];\n";
    o << "    for (int i = 0; i < 30; ++i) lengths[i] = 5;\n";
    o << "    build_tree(t, lengths, 30);\n";
    o << "}\n";
    o << "static const unsigned short lenBase[29] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};\n";
    o << "static const unsigned short lenExt[29] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};\n";
    o << "static const unsigned short distBase[30] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385};\n";
    o << "static const unsigned short distExt[30] = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};\n";
    o << "static unsigned int rawInflate(const unsigned char* src, unsigned int srclen,\n";
    o << "                               unsigned char* dest, unsigned int destcap) {\n";
    o << "    struct Decomp d = {src, srclen, 0, 0, dest, destcap, 0};\n";
    o << "    // bitcount==0 -> getbit 自动装载前 4 字节\n";
    o << "    struct HuffTree litTree, distTree;\n";
    o << "    int finalBlock = 0;\n";
    o << "    while (!finalBlock) {\n";
    o << "        finalBlock = (int)getbit(&d);\n";
    o << "        unsigned int btype = (unsigned int)getbits(&d, 2);\n";
    o << "        if (btype == 0) {\n";
    o << "            while (d.bitcount % 8) getbit(&d);\n";
    o << "            unsigned int lb = getbits(&d, 16);\n";
    o << "            unsigned int hb = getbits(&d, 16);\n";
    o << "            for (unsigned int i = 0; i < lb; ++i) {\n";
    o << "                if (d.outpos >= destcap) return (unsigned int)-1;\n";
    o << "                dest[d.outpos++] = (unsigned char)getbits(&d, 8);\n";
    o << "            }\n";
    o << "            for (unsigned int i = 0; i < hb; ++i) {\n";
    o << "                if (d.outpos >= destcap) return (unsigned int)-1;\n";
    o << "                dest[d.outpos++] = (unsigned char)getbits(&d, 8);\n";
    o << "            }\n";
    o << "        } else if (btype == 1 || btype == 2) {\n";
    o << "            if (btype == 1) { buildFixedLit(&litTree); buildFixedDist(&distTree); }\n";
    o << "            else {\n";
    o << "                unsigned int hlit = getbits(&d, 5) + 257;\n";
    o << "                unsigned int hdist = getbits(&d, 5) + 1;\n";
    o << "                unsigned int hclen = getbits(&d, 4) + 4;\n";
    o << "                const unsigned char order[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};\n";
    o << "                unsigned char clen[19] = {};\n";
    o << "                for (unsigned int i = 0; i < hclen; ++i) clen[order[i]] = (unsigned char)getbits(&d, 3);\n";
    o << "                struct HuffTree clTree;\n";
    o << "                build_tree(&clTree, clen, 19);\n";
    o << "                unsigned char lengths[288 + 30] = {};\n";
    o << "                unsigned int idx = 0;\n";
    o << "                while (idx < hlit + hdist) {\n";
    o << "                    int sym = decode_symbol(&d, &clTree);\n";
    o << "                    if (sym < 0) return (unsigned int)-1;\n";
    o << "                    if (sym < 16) { lengths[idx++] = (unsigned char)sym; }\n";
    o << "                    else {\n";
    o << "                        int rep = 0; unsigned char val = 0;\n";
    o << "                        if (sym == 16) { rep = 3 + (int)getbits(&d, 2); val = lengths[idx - 1]; }\n";
    o << "                        else if (sym == 17) { rep = 3 + (int)getbits(&d, 3); val = 0; }\n";
    o << "                        else { rep = 11 + (int)getbits(&d, 7); val = 0; }\n";
    o << "                        for (int k = 0; k < rep && idx < hlit + hdist; ++k) lengths[idx++] = val;\n";
    o << "                    }\n";
    o << "                }\n";
    o << "                build_tree(&litTree, lengths, hlit);\n";
    o << "                build_tree(&distTree, lengths + hlit, hdist);\n";
    o << "            }\n";
    o << "            while (true) {\n";
    o << "                int sym = decode_symbol(&d, &litTree);\n";
    o << "                if (sym < 0) return (unsigned int)-1;\n";
    o << "                if (sym < 256) {\n";
    o << "                    if (d.outpos >= destcap) return (unsigned int)-1;\n";
    o << "                    dest[d.outpos++] = (unsigned char)sym;\n";
    o << "                } else if (sym == 256) break;\n";
    o << "                else {\n";
    o << "                    sym -= 257;\n";
    o << "                    if (sym >= 29) return (unsigned int)-1;\n";
    o << "                    unsigned int len = lenBase[sym] + getbits(&d, lenExt[sym]);\n";
    o << "                    int dsym = decode_symbol(&d, &distTree);\n";
    o << "                    if (dsym < 0 || dsym >= 30) return (unsigned int)-1;\n";
    o << "                    unsigned int dist = distBase[dsym] + getbits(&d, distExt[dsym]);\n";
    o << "                    if (dist > d.outpos) return (unsigned int)-1;\n";
    o << "                    for (unsigned int i = 0; i < len; ++i) {\n";
    o << "                        if (d.outpos >= destcap) return (unsigned int)-1;\n";
    o << "                        dest[d.outpos] = dest[d.outpos - dist];\n";
    o << "                        d.outpos++;\n";
    o << "                    }\n";
    o << "                }\n";
    o << "            }\n";
    o << "        } else return (unsigned int)-1;\n";
    o << "        if (d.srclen == 0 && finalBlock) break;\n";
    o << "    }\n";
    o << "    return d.outpos;\n";
    o << "}\n";
    o << "} // namespace tinfl\n";
    }
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
        std::string payload = compress ? gzip_compress(content) : content;
        if (payload.empty()) payload = content;   // gzip 失败回退原始数据
        std::string b64 = base64_encode(payload);

        o << "\n";
        o << "  // " << f.route << "  (" << f.mime << ", " << f.size << " bytes, md5=" << f.md5_hex << ")\n";
        for (const auto& route : routesFor(f, alias))
        {
            o << "  svr.Get(R\"(" << route << ")\", [](const httplib::Request&, httplib::Response& res) {\n";
            if (compress) {
                o << "    auto gz = decode_payload(R\"B64(" << b64 << ")B64\");\n";
    o << "    if (gz.size() < 20) { res.set_content(\"bad gzip\", \"text/plain\"); return; }\n";
    o << "    const unsigned char* gp = reinterpret_cast<const unsigned char*>(gz.data());\n";
    o << "    if (gp[0] != 0x1F || gp[1] != 0x8B || gp[2] != 8) { res.set_content(\"bad gzip magic\", \"text/plain\"); return; }\n";
    o << "    unsigned int flg = gp[3];\n";
    o << "    std::size_t hdr = 10;\n";
    o << "    if (flg & 0x04) { hdr += 2 + (unsigned int)(gp[hdr] | (gp[hdr+1] << 8)); }\n";
    o << "    if (flg & 0x08) { while (hdr < gz.size() && gz[hdr] != 0) ++hdr; ++hdr; }\n";
    o << "    if (flg & 0x10) { while (hdr < gz.size() && gz[hdr] != 0) ++hdr; ++hdr; }\n";
    o << "    if (flg & 0x02) hdr += 2;\n";
    o << "    const unsigned char* src = gp + hdr;\n";
    o << "    unsigned int src_len = static_cast<unsigned int>(gz.size() - hdr - 8);\n";
                o << "    std::vector<unsigned char> out_buf(1024 * 1024);\n";
                o << "    unsigned int n = tinfl::rawInflate(src, src_len, out_buf.data(), static_cast<unsigned int>(out_buf.size()));\n";
                o << "    if (n == (unsigned int)-1) { res.set_content(\"inflate error\", \"text/plain\"); return; }\n";
                o << "    res.set_content(std::string(reinterpret_cast<char*>(out_buf.data()), n), \"" << f.mime << "\");\n";
            } else {
                o << "    res.set_content(decode_payload(R\"B64(" << b64 << ")B64\"), \"" << f.mime << "\");\n";
            }
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
    bool alias = true, check = false, compress = true;
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
        else if (a == "--no-compress") compress = false;
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

    std::string content = generate(files, ns, fname, alias, compress);

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
