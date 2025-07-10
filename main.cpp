#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <dirent.h>
#include <sys/stat.h>
#include <cstring>
#include <algorithm>

std::string base64_encode(const std::string& in)
{
    static const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in)
    {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0)
        {
            out.push_back(table[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(table[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

std::string escape_cpp(const std::string& s)
{
    std::string out;
    for (char c : s)
    {
        if (c == '\"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else out += c;
    }
    return out;
}

std::string mime_type(const std::string& path)
{
    auto dot = path.find_last_of('.');
    if (dot == std::string::npos) return "application/octet-stream";
    std::string ext = path.substr(dot + 1);
    if (ext == "html" || ext == "htm") return "text/html";
    if (ext == "css") return "text/css";
    if (ext == "js") return "application/javascript";
    if (ext == "json") return "application/json";
    if (ext == "svg") return "image/svg+xml";
    if (ext == "png") return "image/png";
    if (ext == "jpg" || ext == "jpeg") return "image/jpeg";
    if (ext == "ico") return "image/x-icon";
    if (ext == "txt") return "text/plain";
    return "application/octet-stream";
}

void process_dir(std::ofstream& out, const std::string& base, const std::string& rel)
{
    std::string full = base + "/" + rel;
    DIR* dir = opendir(full.c_str());
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)))
    {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;

        std::string new_rel = rel.empty() ? name : rel + "/" + name;
        std::string new_full = base + "/" + new_rel;

        struct stat st;
        if (stat(new_full.c_str(), &st) == -1) continue;

        if (S_ISDIR(st.st_mode))
        {
            process_dir(out, base, new_rel);
        }
        else if (S_ISREG(st.st_mode))
        {
            std::ifstream file(new_full.c_str(), std::ios::binary);
            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string encoded = base64_encode(buffer.str());

            std::string route = "/" + new_rel;
            std::replace(route.begin(), route.end(), '\\', '/');

            std::string mime = mime_type(name);
            out << "  svr.Get(R\"(" << route << ")\", [](const httplib::Request&, httplib::Response& res) {\n";
            out << "    static const std::string base64 = R\"(" << escape_cpp(encoded) << ")\";\n";
            out << "    res.set_content(base64_decode(base64), \"" << mime << "\");\n";
            out << "  });\n";

            if (route == "/index.html")
            {
                out << "  svr.Get(R\"(/)\", [](const httplib::Request&, httplib::Response& res) {\n";
                out << "    static const std::string base64 = R\"(" << escape_cpp(encoded) << ")\";\n";
                out << "    res.set_content(base64_decode(base64), \"" << mime << "\");\n";
                out << "  });\n";
            }
        }
    }
    closedir(dir);
}

int main(int argc, char* argv[])
{
    if (argc < 3)
    {
        std::cerr << "用法: " << argv[0] << " <web目录> <输出cpp文件>\n";
        return 1;
    }

    std::ofstream out(argv[2]);
    if (!out)
    {
        std::cerr << "无法写入输出文件。\n";
        return 1;
    }

    out << R"(#include "httplib.h"
#include <string>
#include <vector>

// Base64 解码器
static std::string base64_decode(const std::string &in) {
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

void setup_static_routes(httplib::Server& svr) {
)";

    process_dir(out, argv[1], "");
    out << "}\n";

    std::cout << "✅ 生成成功: " << argv[2] << "\n";
    return 0;
}
