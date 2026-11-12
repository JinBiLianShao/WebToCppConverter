# WebToCppConverter v2.1

把静态网页资源（HTML/CSS/JS/图片/字体）转成**单个自包含 C++ 源文件**，页面编进二进制，目标板（如 Zynq）无需部署 www 目录。

## v2.1 更新（gzip 压缩）

- 生成头文件时先 **gzip -9 压缩** 再 base64 编码，HTML/CSS/JS 典型节省 **65~80%**（AntennaLink 实测：456591 → 117100 字节，省 74%）
- 解压函数 **tinfl（RFC 1951 DEFLATE 解压器）内嵌在生成文件里**，带 tinfl 命名空间隔离，**不依赖 liblsx、不依赖 zlib、不依赖任何外部库**——拿到头文件就能用
- 生成代码里的 base64 解码器改名为 decode_payload，避免与宿主工程（如 LSX_LIB::Crypto::base64Decode）符号冲突
- --no-compress 可回退到 v2.0 的直接 base64 模式（不嵌 tinfl、不压缩）

## 特性

| 特性 | 说明 |
|------|------|
| 别名路由 | /xxx.html 与 /xxx 同时生成（3 页面共 7 条路由） |
| 命名空间 | 生成代码包进 webcontent 命名空间，可 --namespace 自定义 |
| 函数名 | 路由注册函数默认 setup_static_routes，可 --fname 自定义 |
| 内容指纹 | 每个资源带 MD5 注释；--check 校验生成文件与 web 目录一致（CI 防陈旧） |
| MIME 表 | 内置 20+ 类型，--mime ext=type 可扩展 |
| 严格检查 | 路由冲突直接报错退出 |
| 子目录 | 递归收集，/sub/page.html 自动注册 |
| 零依赖 | 工具本身单文件 g++ 编译；生成代码只依赖 httplib（宿主自带） |

## 构建

工具零依赖，单文件编译即可：

    g++ -std=c++17 -Wall -Wextra -O2 main.cpp -o build/WebToCppConverter

（仓库自带 CMakeLists 是历史遗留的下游模板，会误扫其他目录；推荐直接用上面的 g++ 命令。）

## 用法

    WebToCppConverter <web目录> <输出cpp文件> [选项]

| 选项 | 说明 |
|------|------|
| --namespace NAME | 生成代码的命名空间（默认 webcontent） |
| --fname NAME | 路由注册函数名（默认 setup_static_routes） |
| --mime ext=type | 追加 MIME 映射，可多次 |
| --check | 校验输出与 web 目录一致，不重写文件 |
| --no-alias | 不生成无扩展名别名路由 |
| --no-compress | 禁用 gzip 压缩（直接 base64 原始数据） |

### 集成到宿主工程

    #include "httplib.h"
    #include "www_webcontent.cpp"   // 生成的头文件

    httplib::Server svr;
    webcontent::setup_static_routes(svr);   // 注册全部页面路由
    svr.listen("0.0.0.0", 8080);

生成文件内部流程：base64Decode → gzip 头解析 → tinfl::rawInflate → 原始页面。每次请求按需解压（1MB 缓冲区，覆盖 100KB 级页面）。

## 测试

    bash tests/test.sh

20 项断言覆盖：压缩/非压缩模式、tinfl 内嵌与自包含编译、别名/子目录路由、MIME、MD5 --check 陈旧检测、自定义命名空间/函数名、大文件压缩率（>5x）、gzip→base64→inflate 解压回环。

## 版本

- v2.1.0 — gzip 压缩内嵌 + 自包含 tinfl 解压器（2026-11-11）
- v2.0.0 — 命名空间隔离、别名路由、MD5 指纹、--check、MIME 扩展、路由冲突检查
- v1.x — 初版 base64 内嵌

## 许可

tinfl 解压器基于 Joergen Ibsen 的 tinf（公有领域）裁剪适配。工具本身由连思鑫（jinbilianshao）维护。
