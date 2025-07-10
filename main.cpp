#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <cstring>

// 使用 POSIX 标准头文件进行目录操作
#include <dirent.h>
#include <sys/stat.h>

// 用于存储文件信息的结构体
struct WebFileInfo {
    std::string route;      // Web 路由路径, e.g., "/css/style.css"
    std::string full_path;  // 文件的完整系统路径
};

// Base64 编码函数
std::string base64_encode(const std::string& in) {
    static const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
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

// 使用 unordered_map 优化 MIME 类型查询
std::string mime_type(const std::string& path) {
    static const std::unordered_map<std::string, std::string> mime_map = {
        {".html", "text/html"}, {".htm",  "text/html"},
        {".css",  "text/css"},  {".js",   "application/javascript"},
        {".json", "application/json"}, {".svg",  "image/svg+xml"},
        {".png",  "image/png"}, {".jpg",  "image/jpeg"},
        {".jpeg", "image/jpeg"}, {".ico",  "image/x-icon"},
        {".txt",  "text/plain"}
    };
    auto dot_pos = path.find_last_of('.');
    if (dot_pos == std::string::npos) {
        return "application/octet-stream";
    }
    std::string ext = path.substr(dot_pos);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    auto it = mime_map.find(ext);
    if (it != mime_map.end()) {
        return it->second;
    }
    return "application/octet-stream";
}

// 递归搜集文件的辅助函数 (使用 POSIX API)
void collect_files_recursive(std::vector<WebFileInfo>& files, const std::string& base_path, const std::string& relative_path) {
    std::string full_dir_path = relative_path.empty() ? base_path : base_path + "/" + relative_path;
    DIR* dir = opendir(full_dir_path.c_str());
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir))) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;

        std::string new_full_path = full_dir_path + "/" + name;
        std::string new_relative_path = relative_path.empty() ? name : relative_path + "/" + name;

        struct stat st;
        if (stat(new_full_path.c_str(), &st) == -1) continue;

        if (S_ISDIR(st.st_mode)) {
            collect_files_recursive(files, base_path, new_relative_path);
        } else if (S_ISREG(st.st_mode)) {
            files.push_back({ "/" + new_relative_path, new_full_path });
        }
    }
    closedir(dir);
}

// 搜集指定目录下所有文件的入口函数
std::vector<WebFileInfo> collect_web_files(const std::string& base_path) {
    std::vector<WebFileInfo> files;
    collect_files_recursive(files, base_path, "");

    // 按字母顺序排序，使生成的注释更整洁
    std::sort(files.begin(), files.end(), [](const auto& a, const auto& b) {
        return a.route < b.route;
    });

    return files;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "用法: " << argv[0] << " <web目录> <输出cpp文件>\n";
        return 1;
    }

    std::string web_dir = argv[1];
    std::string output_file = argv[2];

    // 1. 首先搜集所有文件信息
    auto web_files = collect_web_files(web_dir);
    if (web_files.empty()) {
        std::cerr << "警告: 在 \"" << web_dir << "\" 中未找到任何文件。\n";
    }

    std::ofstream out(output_file);
    if (!out) {
        std::cerr << "错误: 无法写入输出文件 \"" << output_file << "\"\n";
        return 1;
    }

    // 2. 写入 C++ 文件头部和辅助函数
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
)";

    // 3. 写入静态路由列表注释
    out << "/*\n";
    out << " * 可用的静态路由列表:\n";
    for (const auto& file_info : web_files) {
        out << " * - " << file_info.route << "\n";
        if (file_info.route == "/index.html") {
            out << " * - / (根目录映射到 index.html)\n";
        }
    }
    out << " */\n";

    // 4. 写入路由设置函数
    out << "void setup_static_routes(httplib::Server& svr) {\n";

    // 5. 遍历文件信息并生成每个路由的处理代码
    for (const auto& file_info : web_files) {
        std::ifstream file(file_info.full_path, std::ios::binary);
        if (!file) continue;

        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string encoded = base64_encode(buffer.str());
        std::string mime = mime_type(file_info.full_path);

        out << "  svr.Get(R\"(" << file_info.route << ")\", [](const httplib::Request&, httplib::Response& res) {\n";
        out << "    res.set_content(base64_decode(R\"(" << encoded << ")\"), \"" << mime << "\");\n";
        out << "  });\n\n";

        // 为 index.html 添加根目录 ("/") 路由
        if (file_info.route == "/index.html") {
            out << "  svr.Get(R\"(/)\", [](const httplib::Request&, httplib::Response& res) {\n";
            out << "    res.set_content(base64_decode(R\"(" << encoded << ")\"), \"" << mime << "\");\n";
            out << "  });\n\n";
        }
    }

    out << "}\n";

    std::cout << "✅ 生成成功: " << output_file << "\n";
    return 0;
}