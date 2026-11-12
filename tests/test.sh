#!/bin/bash
# WebToCppConverter v2.1 深度测试
set -u
cd "$(dirname "$0")/.."
TOOL=./build/WebToCppConverter
WORK=/tmp/wtc_test
mkdir -p "$WORK/web" "$WORK/out"
printf '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>Test</title></head><body><h1>Hello WebToCppConverter</h1></body></html>' > "$WORK/web/index.html"
printf '<html><body>about</body></html>' > "$WORK/web/about.html"
printf 'body { color: red; }' > "$WORK/web/style.css"
printf 'console.log("hi");' > "$WORK/web/app.js"
mkdir -p "$WORK/web/sub"
printf '<html>sub page</html>' > "$WORK/web/sub/page.html"

pass=0; fail=0
chk() { if [ "$2" = "$3" ]; then echo "[PASS] $1"; pass=$((pass+1)); else echo "[FAIL] $1 (got:$2 want:$3)"; fail=$((fail+1)); fi; }
chksub() { if echo "$2" | grep -q "$3"; then echo "[PASS] $1"; pass=$((pass+1)); else echo "[FAIL] $1"; fail=$((fail+1)); fi; }

echo "========= WebToCppConverter v2.1 深度测试 ========="

$TOOL "$WORK/web" "$WORK/out/gen.cpp" > "$WORK/log" 2>&1
chk "compress generate exit" "$?" "0"
chksub "tinfl namespace embedded" "$(cat "$WORK/out/gen.cpp")" "namespace tinfl"
chksub "miniz tinfl embedded" "$(cat "$WORK/out/gen.cpp")" "tinfl_decompress_mem_to_mem"
chksub "alias route generated" "$(cat "$WORK/out/gen.cpp")" '/index'
chksub "subdir route generated" "$(cat "$WORK/out/gen.cpp")" '/sub/page.html'
chksub "css mime" "$(cat "$WORK/out/gen.cpp")" "text/css"
chksub "js mime" "$(cat "$WORK/out/gen.cpp")" "application/javascript"

$TOOL "$WORK/web" "$WORK/out/gen.cpp" --check > "$WORK/check" 2>&1
chk "--check OK" "$?" "0"
chksub "--check message" "$(cat "$WORK/check")" "CHECK OK"
printf '<html>CHANGED</html>' > "$WORK/web/about.html"
$TOOL "$WORK/web" "$WORK/out/gen.cpp" --check > /dev/null 2>&1
chk "--check detects stale" "$?" "1"

$TOOL "$WORK/web" "$WORK/out/plain.cpp" --no-compress > /dev/null 2>&1
chk "no-compress exit" "$?" "0"
r=$(grep -c 'rawInflate' "$WORK/out/plain.cpp")
chk "no-compress omits tinfl" "$r" "0"

# 大文件压缩率验证
python3 -c "open('$WORK/big.html','w').write('<html>' + 'A'*100000 + '</html>')"
mkdir -p "$WORK/webbig"
cp "$WORK/big.html" "$WORK/webbig/big.html"
$TOOL "$WORK/webbig" "$WORK/out/big_comp.cpp" > /dev/null 2>&1
$TOOL "$WORK/webbig" "$WORK/out/big_plain.cpp" --no-compress > /dev/null 2>&1
csz=$(wc -c < "$WORK/out/big_comp.cpp")
psz=$(wc -c < "$WORK/out/big_plain.cpp")
chk "gzip reduces embedded size (>5x)" "$((csz * 5 < psz))" "1"

$TOOL "$WORK/web" "$WORK/out/custom.cpp" --namespace myweb --fname register_pages > /dev/null 2>&1
chksub "custom namespace" "$(cat "$WORK/out/custom.cpp")" "namespace myweb"
chksub "custom fname" "$(cat "$WORK/out/custom.cpp")" "register_pages"
$TOOL "$WORK/web" "$WORK/out/mime.cpp" --mime xyz=application/x-xyz > /dev/null 2>&1
chk "mime param exit" "$?" "0"
$TOOL "$WORK/web" "$WORK/out/noalias.cpp" --no-alias > /dev/null 2>&1
r=$(grep -c 'svr.Get(R"/index")' "$WORK/out/noalias.cpp")
chk "no-alias omits /index" "$r" "0"

# 生成代码自包含编译验证
cat > "$WORK/out/compile_probe.cpp" << 'CPPEOF'
#include "httplib.h"
#include <string>
#include <vector>
#include <cstdint>
#include "gen.cpp"
int main() { httplib::Server svr; webcontent::setup_static_routes(svr); return 0; }
CPPEOF
LSX=/home/lsx/work/liblsx
timeout 90 g++ -std=c++17 -I"$WORK/out" -I"$LSX/Include/Http" -c "$WORK/out/compile_probe.cpp" -o "$WORK/out/probe.o" > "$WORK/compilelog" 2>&1
chk "generated code compiles standalone" "$?" "0"

# gzip -> base64 -> tinfl 解压回环
cat > "$WORK/out/roundtrip.cpp" << 'CPPEOF'
#include <cstdio>
#include <string>
#include <vector>
#include "gen.cpp"
int main() {
    std::string b64 = "H4sIAAAAAAAC/8tIzcnJVyjPL8pJAQCFEUoNCwAAAA==";
    std::string gz = webcontent::decode_payload(b64);
    if (gz.size() < 20) { printf("bad gzip size"); return 1; }
    unsigned int flg = (unsigned char)gz[3];
    std::size_t hdr = 10;
    if (flg & 0x08) { while (hdr < gz.size() && gz[hdr] != 0) ++hdr; ++hdr; }
    const unsigned char* src = (const unsigned char*)gz.data() + hdr;
    unsigned int src_len = gz.size() - hdr - 8;
    std::vector<unsigned char> out(64 * 1024);
    size_t n = webcontent::tinfl::tinfl_decompress_mem_to_mem(out.data(), out.size(), src, src_len, TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
    if (n == TINFL_DECOMPRESS_MEM_TO_MEM_FAILED) { printf("inflate failed"); return 1; }
    std::string page((char*)out.data(), n);
    if (page != "hello world") { printf("mismatch"); return 1; }
    printf("roundtrip OK: %zu bytes", n);
    return 0;
}
CPPEOF
timeout 60 g++ -std=c++17 -I"$WORK/out" -I"$LSX/Include/Http" "$WORK/out/roundtrip.cpp" -o "$WORK/out/roundtrip" > "$WORK/rtlog" 2>&1
chk "roundtrip code compiles" "$?" "0"
r=$(timeout 10 "$WORK/out/roundtrip" 2>&1)
chksub "gzip->base64->inflate roundtrip" "$r" "roundtrip OK"

echo "========== 汇总: $pass 通过 / $fail 失败 =========="
exit $((fail > 0))
