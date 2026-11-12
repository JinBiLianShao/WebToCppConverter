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
static const char* TINFL_BUNDLE = R"WTCBUNDLE(
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef unsigned char mz_uint8;
typedef signed char mz_int8;
typedef unsigned short mz_uint16;
typedef short mz_int16;
typedef unsigned int mz_uint;
typedef unsigned int mz_uint32;
typedef unsigned long long mz_uint64;
#define MZ_ASSERT(x) ((void)0)
#define MZ_MALLOC(x) malloc(x)
#define MZ_FREE(x) free(x)
#define MZ_REALLOC(p, x) realloc(p, x)
#define MZ_MAX(a,b) (((a)>(b))?(a):(b))
#define MZ_MIN(a,b) (((a)<(b))?(a):(b))
#define MZ_CLEAR_ARR(a) memset((a), 0, sizeof(a))
#define MZ_READ_LE16(p) ((mz_uint16)(((const mz_uint8*)(p))[0]) | ((mz_uint16)(((const mz_uint8*)(p))[1]) << 8))
#define MZ_READ_LE32(p) ((mz_uint32)(((const mz_uint8*)(p))[0]) | ((mz_uint32)(((const mz_uint8*)(p))[1]) << 8) | ((mz_uint32)(((const mz_uint8*)(p))[2]) << 16) | ((mz_uint32)(((const mz_uint8*)(p))[3]) << 24))
#define MZ_MACRO_END while (0)
#define MINIZ_EXPORT
#define TINFL_FLAG_PARSE_ZLIB_HEADER 1
#define TINFL_FLAG_HAS_MORE_INPUT 2
#define TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF 4
#define TINFL_FLAG_COMPUTE_ADLER32 8
#define TINFL_DECOMPRESS_MEM_TO_MEM_FAILED ((size_t)(-1))
typedef enum {
    TINFL_STATUS_FAILED_CANNOT_MAKE_PROGRESS = -4,
    TINFL_STATUS_BAD_PARAM = -3,
    TINFL_STATUS_ADLER32_MISMATCH = -2,
    TINFL_STATUS_FAILED = -1,
    TINFL_STATUS_DONE = 0,
    TINFL_STATUS_NEEDS_MORE_INPUT = 1,
    TINFL_STATUS_HAS_MORE_OUTPUT = 2
} tinfl_status;
#define tinfl_init(r) do { (r)->m_state = 0; } MZ_MACRO_END
#define tinfl_get_adler32(r) (r)->m_check_adler32
enum {
    TINFL_MAX_HUFF_TABLES = 3,
    TINFL_MAX_HUFF_SYMBOLS_0 = 288,
    TINFL_MAX_HUFF_SYMBOLS_1 = 32,
    TINFL_MAX_HUFF_SYMBOLS_2 = 19,
    TINFL_FAST_LOOKUP_BITS = 10,
    TINFL_FAST_LOOKUP_SIZE = 1 << TINFL_FAST_LOOKUP_BITS
};
#define TINFL_USE_64BIT_BITBUF 0
typedef mz_uint32 tinfl_bit_buf_t;
#define TINFL_BITBUF_SIZE 32
struct tinfl_decompressor_tag {
    mz_uint32 m_state, m_num_bits, m_zhdr0, m_zhdr1, m_z_adler32, m_final, m_type, m_check_adler32, m_dist, m_counter, m_num_extra, m_table_sizes[TINFL_MAX_HUFF_TABLES];
    tinfl_bit_buf_t m_bit_buf;
    size_t m_dist_from_out_buf_start;
    mz_int16 m_look_up[TINFL_MAX_HUFF_TABLES][TINFL_FAST_LOOKUP_SIZE];
    mz_int16 m_tree_0[TINFL_MAX_HUFF_SYMBOLS_0 * 2];
    mz_int16 m_tree_1[TINFL_MAX_HUFF_SYMBOLS_1 * 2];
    mz_int16 m_tree_2[TINFL_MAX_HUFF_SYMBOLS_2 * 2];
    mz_uint8 m_code_size_0[TINFL_MAX_HUFF_SYMBOLS_0];
    mz_uint8 m_code_size_1[TINFL_MAX_HUFF_SYMBOLS_1];
    mz_uint8 m_code_size_2[TINFL_MAX_HUFF_SYMBOLS_2];
    mz_uint8 m_raw_header[4], m_len_codes[TINFL_MAX_HUFF_SYMBOLS_0 + TINFL_MAX_HUFF_SYMBOLS_1 + 137];
};
typedef struct tinfl_decompressor_tag tinfl_decompressor;
typedef int (*tinfl_put_buf_func_ptr)(const void *pBuf, int len, void *pUser);
#define TINFL_LZ_DICT_SIZE 32768
/**************************************************************************
 *
 * Copyright 2013-2014 RAD Game Tools and Valve Software
 * Copyright 2010-2014 Rich Geldreich and Tenacious Software LLC
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 **************************************************************************/


#ifndef MINIZ_NO_INFLATE_APIS

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

    /* ------------------- Low-level Decompression (completely independent from all compression API's) */

#define TINFL_MEMCPY(d, s, l) memcpy(d, s, l)
#define TINFL_MEMSET(p, c, l) memset(p, c, l)

#define TINFL_CR_BEGIN  \
    switch (r->m_state) \
    {                   \
        case 0:
#define TINFL_CR_RETURN(state_index, result) \
    do                                       \
    {                                        \
        status = result;                     \
        r->m_state = state_index;            \
        goto common_exit;                    \
        case state_index:;                   \
    }                                        \
    MZ_MACRO_END
#define TINFL_CR_RETURN_FOREVER(state_index, result) \
    do                                               \
    {                                                \
        for (;;)                                     \
        {                                            \
            TINFL_CR_RETURN(state_index, result);    \
        }                                            \
    }                                                \
    MZ_MACRO_END
#define TINFL_CR_FINISH }

#define TINFL_GET_BYTE(state_index, c)                                                                                                                           \
    do                                                                                                                                                           \
    {                                                                                                                                                            \
        while (pIn_buf_cur >= pIn_buf_end)                                                                                                                       \
        {                                                                                                                                                        \
            TINFL_CR_RETURN(state_index, (decomp_flags & TINFL_FLAG_HAS_MORE_INPUT) ? TINFL_STATUS_NEEDS_MORE_INPUT : TINFL_STATUS_FAILED_CANNOT_MAKE_PROGRESS); \
        }                                                                                                                                                        \
        c = *pIn_buf_cur++;                                                                                                                                      \
    }                                                                                                                                                            \
    MZ_MACRO_END

#define TINFL_NEED_BITS(state_index, n)                \
    do                                                 \
    {                                                  \
        mz_uint c;                                     \
        TINFL_GET_BYTE(state_index, c);                \
        bit_buf |= (((tinfl_bit_buf_t)c) << num_bits); \
        num_bits += 8;                                 \
    } while (num_bits < (mz_uint)(n))
#define TINFL_SKIP_BITS(state_index, n)      \
    do                                       \
    {                                        \
        if (num_bits < (mz_uint)(n))         \
        {                                    \
            TINFL_NEED_BITS(state_index, n); \
        }                                    \
        bit_buf >>= (n);                     \
        num_bits -= (n);                     \
    }                                        \
    MZ_MACRO_END
#define TINFL_GET_BITS(state_index, b, n)    \
    do                                       \
    {                                        \
        if (num_bits < (mz_uint)(n))         \
        {                                    \
            TINFL_NEED_BITS(state_index, n); \
        }                                    \
        b = bit_buf & ((1 << (n)) - 1);      \
        bit_buf >>= (n);                     \
        num_bits -= (n);                     \
    }                                        \
    MZ_MACRO_END

/* TINFL_HUFF_BITBUF_FILL() is only used rarely, when the number of bytes remaining in the input buffer falls below 2. */
/* It reads just enough bytes from the input stream that are needed to decode the next Huffman code (and absolutely no more). It works by trying to fully decode a */
/* Huffman code by using whatever bits are currently present in the bit buffer. If this fails, it reads another byte, and tries again until it succeeds or until the */
/* bit buffer contains >=15 bits (deflate's max. Huffman code size). */
#define TINFL_HUFF_BITBUF_FILL(state_index, pLookUp, pTree)          \
    do                                                               \
    {                                                                \
        temp = pLookUp[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)];      \
        if (temp >= 0)                                               \
        {                                                            \
            code_len = temp >> 9;                                    \
            if ((code_len) && (num_bits >= code_len))                \
                break;                                               \
        }                                                            \
        else if (num_bits > TINFL_FAST_LOOKUP_BITS)                  \
        {                                                            \
            code_len = TINFL_FAST_LOOKUP_BITS;                       \
            do                                                       \
            {                                                        \
                temp = pTree[~temp + ((bit_buf >> code_len++) & 1)]; \
            } while ((temp < 0) && (num_bits >= (code_len + 1)));    \
            if (temp >= 0)                                           \
                break;                                               \
        }                                                            \
        TINFL_GET_BYTE(state_index, c);                              \
        bit_buf |= (((tinfl_bit_buf_t)c) << num_bits);               \
        num_bits += 8;                                               \
    } while (num_bits < 15);

/* TINFL_HUFF_DECODE() decodes the next Huffman coded symbol. It's more complex than you would initially expect because the zlib API expects the decompressor to never read */
/* beyond the final byte of the deflate stream. (In other words, when this macro wants to read another byte from the input, it REALLY needs another byte in order to fully */
/* decode the next Huffman code.) Handling this properly is particularly important on raw deflate (non-zlib) streams, which aren't followed by a byte aligned adler-32. */
/* The slow path is only executed at the very end of the input buffer. */
/* v1.16: The original macro handled the case at the very end of the passed-in input buffer, but we also need to handle the case where the user passes in 1+zillion bytes */
/* following the deflate data and our non-conservative read-ahead path won't kick in here on this code. This is much trickier. */
#define TINFL_HUFF_DECODE(state_index, sym, pLookUp, pTree)                                                                         \
    do                                                                                                                              \
    {                                                                                                                               \
        int temp;                                                                                                                   \
        mz_uint code_len, c;                                                                                                        \
        if (num_bits < 15)                                                                                                          \
        {                                                                                                                           \
            if ((pIn_buf_end - pIn_buf_cur) < 2)                                                                                    \
            {                                                                                                                       \
                TINFL_HUFF_BITBUF_FILL(state_index, pLookUp, pTree);                                                                \
            }                                                                                                                       \
            else                                                                                                                    \
            {                                                                                                                       \
                bit_buf |= (((tinfl_bit_buf_t)pIn_buf_cur[0]) << num_bits) | (((tinfl_bit_buf_t)pIn_buf_cur[1]) << (num_bits + 8)); \
                pIn_buf_cur += 2;                                                                                                   \
                num_bits += 16;                                                                                                     \
            }                                                                                                                       \
        }                                                                                                                           \
        if ((temp = pLookUp[bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)]) >= 0)                                                          \
            code_len = temp >> 9, temp &= 511;                                                                                      \
        else                                                                                                                        \
        {                                                                                                                           \
            code_len = TINFL_FAST_LOOKUP_BITS;                                                                                      \
            do                                                                                                                      \
            {                                                                                                                       \
                temp = pTree[~temp + ((bit_buf >> code_len++) & 1)];                                                                \
            } while (temp < 0);                                                                                                     \
        }                                                                                                                           \
        sym = temp;                                                                                                                 \
        bit_buf >>= code_len;                                                                                                       \
        num_bits -= code_len;                                                                                                       \
    }                                                                                                                               \
    MZ_MACRO_END

    static void tinfl_clear_tree(tinfl_decompressor *r)
    {
        if (r->m_type == 0)
            MZ_CLEAR_ARR(r->m_tree_0);
        else if (r->m_type == 1)
            MZ_CLEAR_ARR(r->m_tree_1);
        else
            MZ_CLEAR_ARR(r->m_tree_2);
    }

    tinfl_status tinfl_decompress(tinfl_decompressor *r, const mz_uint8 *pIn_buf_next, size_t *pIn_buf_size, mz_uint8 *pOut_buf_start, mz_uint8 *pOut_buf_next, size_t *pOut_buf_size, const mz_uint32 decomp_flags)
    {
        static const mz_uint16 s_length_base[31] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0 };
        static const mz_uint8 s_length_extra[31] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0, 0, 0 };
        static const mz_uint16 s_dist_base[32] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 0, 0 };
        static const mz_uint8 s_dist_extra[32] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };
        static const mz_uint8 s_length_dezigzag[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
        static const mz_uint16 s_min_table_sizes[3] = { 257, 1, 4 };

        mz_int16 *pTrees[3];
        mz_uint8 *pCode_sizes[3];

        tinfl_status status = TINFL_STATUS_FAILED;
        mz_uint32 num_bits, dist, counter, num_extra;
        tinfl_bit_buf_t bit_buf;
        const mz_uint8 *pIn_buf_cur = pIn_buf_next, *const pIn_buf_end = pIn_buf_next + *pIn_buf_size;
        mz_uint8 *pOut_buf_cur = pOut_buf_next, *const pOut_buf_end = pOut_buf_next ? pOut_buf_next + *pOut_buf_size : NULL;
        size_t out_buf_size_mask = (decomp_flags & TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF) ? (size_t)-1 : ((pOut_buf_next - pOut_buf_start) + *pOut_buf_size) - 1, dist_from_out_buf_start;

        /* Ensure the output buffer's size is a power of 2, unless the output buffer is large enough to hold the entire output file (in which case it doesn't matter). */
        if (((out_buf_size_mask + 1) & out_buf_size_mask) || (pOut_buf_next < pOut_buf_start))
        {
            *pIn_buf_size = *pOut_buf_size = 0;
            return TINFL_STATUS_BAD_PARAM;
        }

        pTrees[0] = r->m_tree_0;
        pTrees[1] = r->m_tree_1;
        pTrees[2] = r->m_tree_2;
        pCode_sizes[0] = r->m_code_size_0;
        pCode_sizes[1] = r->m_code_size_1;
        pCode_sizes[2] = r->m_code_size_2;

        num_bits = r->m_num_bits;
        bit_buf = r->m_bit_buf;
        dist = r->m_dist;
        counter = r->m_counter;
        num_extra = r->m_num_extra;
        dist_from_out_buf_start = r->m_dist_from_out_buf_start;
        TINFL_CR_BEGIN

        bit_buf = num_bits = dist = counter = num_extra = r->m_zhdr0 = r->m_zhdr1 = 0;
        r->m_z_adler32 = r->m_check_adler32 = 1;
        if (decomp_flags & TINFL_FLAG_PARSE_ZLIB_HEADER)
        {
            TINFL_GET_BYTE(1, r->m_zhdr0);
            TINFL_GET_BYTE(2, r->m_zhdr1);
            counter = (((r->m_zhdr0 * 256 + r->m_zhdr1) % 31 != 0) || (r->m_zhdr1 & 32) || ((r->m_zhdr0 & 15) != 8));
            if (!(decomp_flags & TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF))
                counter |= (((1U << (8U + (r->m_zhdr0 >> 4))) > 32768U) || ((out_buf_size_mask + 1) < (size_t)((size_t)1 << (8U + (r->m_zhdr0 >> 4)))));
            if (counter)
            {
                TINFL_CR_RETURN_FOREVER(36, TINFL_STATUS_FAILED);
            }
        }

        do
        {
            TINFL_GET_BITS(3, r->m_final, 3);
            r->m_type = r->m_final >> 1;
            if (r->m_type == 0)
            {
                TINFL_SKIP_BITS(5, num_bits & 7);
                for (counter = 0; counter < 4; ++counter)
                {
                    if (num_bits)
                        TINFL_GET_BITS(6, r->m_raw_header[counter], 8);
                    else
                        TINFL_GET_BYTE(7, r->m_raw_header[counter]);
                }
                if ((counter = (r->m_raw_header[0] | (r->m_raw_header[1] << 8))) != (mz_uint)(0xFFFF ^ (r->m_raw_header[2] | (r->m_raw_header[3] << 8))))
                {
                    TINFL_CR_RETURN_FOREVER(39, TINFL_STATUS_FAILED);
                }
                while ((counter) && (num_bits))
                {
                    TINFL_GET_BITS(51, dist, 8);
                    while (pOut_buf_cur >= pOut_buf_end)
                    {
                        TINFL_CR_RETURN(52, TINFL_STATUS_HAS_MORE_OUTPUT);
                    }
                    *pOut_buf_cur++ = (mz_uint8)dist;
                    counter--;
                }
                while (counter)
                {
                    size_t n;
                    while (pOut_buf_cur >= pOut_buf_end)
                    {
                        TINFL_CR_RETURN(9, TINFL_STATUS_HAS_MORE_OUTPUT);
                    }
                    while (pIn_buf_cur >= pIn_buf_end)
                    {
                        TINFL_CR_RETURN(38, (decomp_flags & TINFL_FLAG_HAS_MORE_INPUT) ? TINFL_STATUS_NEEDS_MORE_INPUT : TINFL_STATUS_FAILED_CANNOT_MAKE_PROGRESS);
                    }
                    n = MZ_MIN(MZ_MIN((size_t)(pOut_buf_end - pOut_buf_cur), (size_t)(pIn_buf_end - pIn_buf_cur)), counter);
                    TINFL_MEMCPY(pOut_buf_cur, pIn_buf_cur, n);
                    pIn_buf_cur += n;
                    pOut_buf_cur += n;
                    counter -= (mz_uint)n;
                }
            }
            else if (r->m_type == 3)
            {
                TINFL_CR_RETURN_FOREVER(10, TINFL_STATUS_FAILED);
            }
            else
            {
                if (r->m_type == 1)
                {
                    mz_uint8 *p = r->m_code_size_0;
                    mz_uint i;
                    r->m_table_sizes[0] = 288;
                    r->m_table_sizes[1] = 32;
                    TINFL_MEMSET(r->m_code_size_1, 5, 32);
                    for (i = 0; i <= 143; ++i)
                        *p++ = 8;
                    for (; i <= 255; ++i)
                        *p++ = 9;
                    for (; i <= 279; ++i)
                        *p++ = 7;
                    for (; i <= 287; ++i)
                        *p++ = 8;
                }
                else
                {
                    for (counter = 0; counter < 3; counter++)
                    {
                        TINFL_GET_BITS(11, r->m_table_sizes[counter], "\05\05\04"[counter]);
                        r->m_table_sizes[counter] += s_min_table_sizes[counter];
                    }
                    MZ_CLEAR_ARR(r->m_code_size_2);
                    for (counter = 0; counter < r->m_table_sizes[2]; counter++)
                    {
                        mz_uint s;
                        TINFL_GET_BITS(14, s, 3);
                        r->m_code_size_2[s_length_dezigzag[counter]] = (mz_uint8)s;
                    }
                    r->m_table_sizes[2] = 19;
                }
                for (; (int)r->m_type >= 0; r->m_type--)
                {
                    int tree_next, tree_cur;
                    mz_int16 *pLookUp;
                    mz_int16 *pTree;
                    mz_uint8 *pCode_size;
                    mz_uint i, j, used_syms, total, sym_index, next_code[17], total_syms[16];
                    pLookUp = r->m_look_up[r->m_type];
                    pTree = pTrees[r->m_type];
                    pCode_size = pCode_sizes[r->m_type];
                    MZ_CLEAR_ARR(total_syms);
                    TINFL_MEMSET(pLookUp, 0, sizeof(r->m_look_up[0]));
                    tinfl_clear_tree(r);
                    for (i = 0; i < r->m_table_sizes[r->m_type]; ++i)
                        total_syms[pCode_size[i]]++;
                    used_syms = 0, total = 0;
                    next_code[0] = next_code[1] = 0;
                    for (i = 1; i <= 15; ++i)
                    {
                        used_syms += total_syms[i];
                        next_code[i + 1] = (total = ((total + total_syms[i]) << 1));
                    }
                    if ((65536 != total) && (used_syms > 1))
                    {
                        TINFL_CR_RETURN_FOREVER(35, TINFL_STATUS_FAILED);
                    }
                    for (tree_next = -1, sym_index = 0; sym_index < r->m_table_sizes[r->m_type]; ++sym_index)
                    {
                        mz_uint rev_code = 0, l, cur_code, code_size = pCode_size[sym_index];
                        if (!code_size)
                            continue;
                        cur_code = next_code[code_size]++;
                        for (l = code_size; l > 0; l--, cur_code >>= 1)
                            rev_code = (rev_code << 1) | (cur_code & 1);
                        if (code_size <= TINFL_FAST_LOOKUP_BITS)
                        {
                            mz_int16 k = (mz_int16)((code_size << 9) | sym_index);
                            while (rev_code < TINFL_FAST_LOOKUP_SIZE)
                            {
                                pLookUp[rev_code] = k;
                                rev_code += (1 << code_size);
                            }
                            continue;
                        }
                        if (0 == (tree_cur = pLookUp[rev_code & (TINFL_FAST_LOOKUP_SIZE - 1)]))
                        {
                            pLookUp[rev_code & (TINFL_FAST_LOOKUP_SIZE - 1)] = (mz_int16)tree_next;
                            tree_cur = tree_next;
                            tree_next -= 2;
                        }
                        rev_code >>= (TINFL_FAST_LOOKUP_BITS - 1);
                        for (j = code_size; j > (TINFL_FAST_LOOKUP_BITS + 1); j--)
                        {
                            tree_cur -= ((rev_code >>= 1) & 1);
                            if (!pTree[-tree_cur - 1])
                            {
                                pTree[-tree_cur - 1] = (mz_int16)tree_next;
                                tree_cur = tree_next;
                                tree_next -= 2;
                            }
                            else
                                tree_cur = pTree[-tree_cur - 1];
                        }
                        tree_cur -= ((rev_code >>= 1) & 1);
                        pTree[-tree_cur - 1] = (mz_int16)sym_index;
                    }
                    if (r->m_type == 2)
                    {
                        for (counter = 0; counter < (r->m_table_sizes[0] + r->m_table_sizes[1]);)
                        {
                            mz_uint s;
                            TINFL_HUFF_DECODE(16, dist, r->m_look_up[2], r->m_tree_2);
                            if (dist < 16)
                            {
                                r->m_len_codes[counter++] = (mz_uint8)dist;
                                continue;
                            }
                            if ((dist == 16) && (!counter))
                            {
                                TINFL_CR_RETURN_FOREVER(17, TINFL_STATUS_FAILED);
                            }
                            num_extra = "\02\03\07"[dist - 16];
                            TINFL_GET_BITS(18, s, num_extra);
                            s += "\03\03\013"[dist - 16];
                            TINFL_MEMSET(r->m_len_codes + counter, (dist == 16) ? r->m_len_codes[counter - 1] : 0, s);
                            counter += s;
                        }
                        if ((r->m_table_sizes[0] + r->m_table_sizes[1]) != counter)
                        {
                            TINFL_CR_RETURN_FOREVER(21, TINFL_STATUS_FAILED);
                        }
                        TINFL_MEMCPY(r->m_code_size_0, r->m_len_codes, r->m_table_sizes[0]);
                        TINFL_MEMCPY(r->m_code_size_1, r->m_len_codes + r->m_table_sizes[0], r->m_table_sizes[1]);
                    }
                }
                for (;;)
                {
                    mz_uint8 *pSrc;
                    for (;;)
                    {
                        if (((pIn_buf_end - pIn_buf_cur) < 4) || ((pOut_buf_end - pOut_buf_cur) < 2))
                        {
                            TINFL_HUFF_DECODE(23, counter, r->m_look_up[0], r->m_tree_0);
                            if (counter >= 256)
                                break;
                            while (pOut_buf_cur >= pOut_buf_end)
                            {
                                TINFL_CR_RETURN(24, TINFL_STATUS_HAS_MORE_OUTPUT);
                            }
                            *pOut_buf_cur++ = (mz_uint8)counter;
                        }
                        else
                        {
                            int sym2;
                            mz_uint code_len;
#if TINFL_USE_64BIT_BITBUF
                            if (num_bits < 30)
                            {
                                bit_buf |= (((tinfl_bit_buf_t)MZ_READ_LE32(pIn_buf_cur)) << num_bits);
                                pIn_buf_cur += 4;
                                num_bits += 32;
                            }
#else
                        if (num_bits < 15)
                        {
                            bit_buf |= (((tinfl_bit_buf_t)MZ_READ_LE16(pIn_buf_cur)) << num_bits);
                            pIn_buf_cur += 2;
                            num_bits += 16;
                        }
#endif /* TINFL_USE_64BIT_BITBUF */
                            if ((sym2 = r->m_look_up[0][bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)]) >= 0)
                                code_len = sym2 >> 9;
                            else
                            {
                                code_len = TINFL_FAST_LOOKUP_BITS;
                                do
                                {
                                    sym2 = r->m_tree_0[~sym2 + ((bit_buf >> code_len++) & 1)];
                                } while (sym2 < 0);
                            }
                            counter = sym2;
                            bit_buf >>= code_len;
                            num_bits -= code_len;
                            if (code_len == 0)
                            {
                                TINFL_CR_RETURN_FOREVER(40, TINFL_STATUS_FAILED);
                            }
                            if (counter & 256)
                                break;

#if !TINFL_USE_64BIT_BITBUF
                            if (num_bits < 15)
                            {
                                bit_buf |= (((tinfl_bit_buf_t)MZ_READ_LE16(pIn_buf_cur)) << num_bits);
                                pIn_buf_cur += 2;
                                num_bits += 16;
                            }
#endif /* !TINFL_USE_64BIT_BITBUF */
                            if ((sym2 = r->m_look_up[0][bit_buf & (TINFL_FAST_LOOKUP_SIZE - 1)]) >= 0)
                                code_len = sym2 >> 9;
                            else
                            {
                                code_len = TINFL_FAST_LOOKUP_BITS;
                                do
                                {
                                    sym2 = r->m_tree_0[~sym2 + ((bit_buf >> code_len++) & 1)];
                                } while (sym2 < 0);
                            }
                            bit_buf >>= code_len;
                            num_bits -= code_len;
                            if (code_len == 0)
                            {
                                TINFL_CR_RETURN_FOREVER(54, TINFL_STATUS_FAILED);
                            }

                            pOut_buf_cur[0] = (mz_uint8)counter;
                            if (sym2 & 256)
                            {
                                pOut_buf_cur++;
                                counter = sym2;
                                break;
                            }
                            pOut_buf_cur[1] = (mz_uint8)sym2;
                            pOut_buf_cur += 2;
                        }
                    }
                    if ((counter &= 511) == 256)
                        break;

                    num_extra = s_length_extra[counter - 257];
                    counter = s_length_base[counter - 257];
                    if (num_extra)
                    {
                        mz_uint extra_bits;
                        TINFL_GET_BITS(25, extra_bits, num_extra);
                        counter += extra_bits;
                    }

                    TINFL_HUFF_DECODE(26, dist, r->m_look_up[1], r->m_tree_1);
                    num_extra = s_dist_extra[dist];
                    dist = s_dist_base[dist];
                    if (num_extra)
                    {
                        mz_uint extra_bits;
                        TINFL_GET_BITS(27, extra_bits, num_extra);
                        dist += extra_bits;
                    }

                    dist_from_out_buf_start = pOut_buf_cur - pOut_buf_start;
                    if ((dist == 0 || dist > dist_from_out_buf_start || dist_from_out_buf_start == 0) && (decomp_flags & TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF))
                    {
                        TINFL_CR_RETURN_FOREVER(37, TINFL_STATUS_FAILED);
                    }

                    pSrc = pOut_buf_start + ((dist_from_out_buf_start - dist) & out_buf_size_mask);

                    if ((MZ_MAX(pOut_buf_cur, pSrc) + counter) > pOut_buf_end)
                    {
                        while (counter--)
                        {
                            while (pOut_buf_cur >= pOut_buf_end)
                            {
                                TINFL_CR_RETURN(53, TINFL_STATUS_HAS_MORE_OUTPUT);
                            }
                            *pOut_buf_cur++ = pOut_buf_start[(dist_from_out_buf_start++ - dist) & out_buf_size_mask];
                        }
                        continue;
                    }
#if MINIZ_USE_UNALIGNED_LOADS_AND_STORES
                    else if ((counter >= 9) && (counter <= dist))
                    {
                        const mz_uint8 *pSrc_end = pSrc + (counter & ~7);
                        do
                        {
#ifdef MINIZ_UNALIGNED_USE_MEMCPY
                            memcpy(pOut_buf_cur, pSrc, sizeof(mz_uint32) * 2);
#else
                            ((mz_uint32 *)pOut_buf_cur)[0] = ((const mz_uint32 *)pSrc)[0];
                            ((mz_uint32 *)pOut_buf_cur)[1] = ((const mz_uint32 *)pSrc)[1];
#endif /* MINIZ_UNALIGNED_USE_MEMCPY */
                            pOut_buf_cur += 8;
                        } while ((pSrc += 8) < pSrc_end);
                        if ((counter &= 7) < 3)
                        {
                            if (counter)
                            {
                                pOut_buf_cur[0] = pSrc[0];
                                if (counter > 1)
                                    pOut_buf_cur[1] = pSrc[1];
                                pOut_buf_cur += counter;
                            }
                            continue;
                        }
                    }
#endif /* MINIZ_USE_UNALIGNED_LOADS_AND_STORES */
                    while (counter > 2)
                    {
                        pOut_buf_cur[0] = pSrc[0];
                        pOut_buf_cur[1] = pSrc[1];
                        pOut_buf_cur[2] = pSrc[2];
                        pOut_buf_cur += 3;
                        pSrc += 3;
                        counter -= 3;
                    }
                    if (counter > 0)
                    {
                        pOut_buf_cur[0] = pSrc[0];
                        if (counter > 1)
                            pOut_buf_cur[1] = pSrc[1];
                        pOut_buf_cur += counter;
                    }
                }
            }
        } while (!(r->m_final & 1));

        /* Ensure byte alignment and put back any bytes from the bitbuf if we've looked ahead too far on gzip, or other Deflate streams followed by arbitrary data. */
        /* I'm being super conservative here. A number of simplifications can be made to the byte alignment part, and the Adler32 check shouldn't ever need to worry about reading from the bitbuf now. */
        TINFL_SKIP_BITS(32, num_bits & 7);
        while ((pIn_buf_cur > pIn_buf_next) && (num_bits >= 8))
        {
            --pIn_buf_cur;
            num_bits -= 8;
        }
        bit_buf &= ~(~(tinfl_bit_buf_t)0 << num_bits);
        MZ_ASSERT(!num_bits); /* if this assert fires then we've read beyond the end of non-deflate/zlib streams with following data (such as gzip streams). */

        if (decomp_flags & TINFL_FLAG_PARSE_ZLIB_HEADER)
        {
            for (counter = 0; counter < 4; ++counter)
            {
                mz_uint s;
                if (num_bits)
                    TINFL_GET_BITS(41, s, 8);
                else
                    TINFL_GET_BYTE(42, s);
                r->m_z_adler32 = (r->m_z_adler32 << 8) | s;
            }
        }
        TINFL_CR_RETURN_FOREVER(34, TINFL_STATUS_DONE);

        TINFL_CR_FINISH

    common_exit:
        /* As long as we aren't telling the caller that we NEED more input to make forward progress: */
        /* Put back any bytes from the bitbuf in case we've looked ahead too far on gzip, or other Deflate streams followed by arbitrary data. */
        /* We need to be very careful here to NOT push back any bytes we definitely know we need to make forward progress, though, or we'll lock the caller up into an inf loop. */
        if ((status != TINFL_STATUS_NEEDS_MORE_INPUT) && (status != TINFL_STATUS_FAILED_CANNOT_MAKE_PROGRESS))
        {
            while ((pIn_buf_cur > pIn_buf_next) && (num_bits >= 8))
            {
                --pIn_buf_cur;
                num_bits -= 8;
            }
        }
        r->m_num_bits = num_bits;
        r->m_bit_buf = bit_buf & ~(~(tinfl_bit_buf_t)0 << num_bits);
        r->m_dist = dist;
        r->m_counter = counter;
        r->m_num_extra = num_extra;
        r->m_dist_from_out_buf_start = dist_from_out_buf_start;
        *pIn_buf_size = pIn_buf_cur - pIn_buf_next;
        *pOut_buf_size = pOut_buf_cur - pOut_buf_next;
        if ((decomp_flags & (TINFL_FLAG_PARSE_ZLIB_HEADER | TINFL_FLAG_COMPUTE_ADLER32)) && (status >= 0))
        {
            const mz_uint8 *ptr = pOut_buf_next;
            size_t buf_len = *pOut_buf_size;
            mz_uint32 i, s1 = r->m_check_adler32 & 0xffff, s2 = r->m_check_adler32 >> 16;
            size_t block_len = buf_len % 5552;
            while (buf_len)
            {
                for (i = 0; i + 7 < block_len; i += 8, ptr += 8)
                {
                    s1 += ptr[0], s2 += s1;
                    s1 += ptr[1], s2 += s1;
                    s1 += ptr[2], s2 += s1;
                    s1 += ptr[3], s2 += s1;
                    s1 += ptr[4], s2 += s1;
                    s1 += ptr[5], s2 += s1;
                    s1 += ptr[6], s2 += s1;
                    s1 += ptr[7], s2 += s1;
                }
                for (; i < block_len; ++i)
                    s1 += *ptr++, s2 += s1;
                s1 %= 65521U, s2 %= 65521U;
                buf_len -= block_len;
                block_len = 5552;
            }
            r->m_check_adler32 = (s2 << 16) + s1;
            if ((status == TINFL_STATUS_DONE) && (decomp_flags & TINFL_FLAG_PARSE_ZLIB_HEADER) && (r->m_check_adler32 != r->m_z_adler32))
                status = TINFL_STATUS_ADLER32_MISMATCH;
        }
        return status;
    }

    /* Higher level helper functions. */
    void *tinfl_decompress_mem_to_heap(const void *pSrc_buf, size_t src_buf_len, size_t *pOut_len, int flags)
    {
        tinfl_decompressor decomp;
        void *pBuf = NULL, *pNew_buf;
        size_t src_buf_ofs = 0, out_buf_capacity = 0;
        *pOut_len = 0;
        tinfl_init(&decomp);
        for (;;)
        {
            size_t src_buf_size = src_buf_len - src_buf_ofs, dst_buf_size = out_buf_capacity - *pOut_len, new_out_buf_capacity;
            tinfl_status status = tinfl_decompress(&decomp, (const mz_uint8 *)pSrc_buf + src_buf_ofs, &src_buf_size, (mz_uint8 *)pBuf, pBuf ? (mz_uint8 *)pBuf + *pOut_len : NULL, &dst_buf_size,
                                                   (flags & ~TINFL_FLAG_HAS_MORE_INPUT) | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
            if ((status < 0) || (status == TINFL_STATUS_NEEDS_MORE_INPUT))
            {
                MZ_FREE(pBuf);
                *pOut_len = 0;
                return NULL;
            }
            src_buf_ofs += src_buf_size;
            *pOut_len += dst_buf_size;
            if (status == TINFL_STATUS_DONE)
                break;
            new_out_buf_capacity = out_buf_capacity * 2;
            if (new_out_buf_capacity < 128)
                new_out_buf_capacity = 128;
            pNew_buf = MZ_REALLOC(pBuf, new_out_buf_capacity);
            if (!pNew_buf)
            {
                MZ_FREE(pBuf);
                *pOut_len = 0;
                return NULL;
            }
            pBuf = pNew_buf;
            out_buf_capacity = new_out_buf_capacity;
        }
        return pBuf;
    }

    size_t tinfl_decompress_mem_to_mem(void *pOut_buf, size_t out_buf_len, const void *pSrc_buf, size_t src_buf_len, int flags)
    {
        tinfl_decompressor decomp;
        tinfl_status status;
        tinfl_init(&decomp);
        status = tinfl_decompress(&decomp, (const mz_uint8 *)pSrc_buf, &src_buf_len, (mz_uint8 *)pOut_buf, (mz_uint8 *)pOut_buf, &out_buf_len, (flags & ~TINFL_FLAG_HAS_MORE_INPUT) | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
        return (status != TINFL_STATUS_DONE) ? TINFL_DECOMPRESS_MEM_TO_MEM_FAILED : out_buf_len;
    }

    int tinfl_decompress_mem_to_callback(const void *pIn_buf, size_t *pIn_buf_size, tinfl_put_buf_func_ptr pPut_buf_func, void *pPut_buf_user, int flags)
    {
        int result = 0;
        tinfl_decompressor decomp;
        mz_uint8 *pDict = (mz_uint8 *)MZ_MALLOC(TINFL_LZ_DICT_SIZE);
        size_t in_buf_ofs = 0, dict_ofs = 0;
        if (!pDict)
            return TINFL_STATUS_FAILED;
        memset(pDict, 0, TINFL_LZ_DICT_SIZE);
        tinfl_init(&decomp);
        for (;;)
        {
            size_t in_buf_size = *pIn_buf_size - in_buf_ofs, dst_buf_size = TINFL_LZ_DICT_SIZE - dict_ofs;
            tinfl_status status = tinfl_decompress(&decomp, (const mz_uint8 *)pIn_buf + in_buf_ofs, &in_buf_size, pDict, pDict + dict_ofs, &dst_buf_size,
                                                   (flags & ~(TINFL_FLAG_HAS_MORE_INPUT | TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF)));
            in_buf_ofs += in_buf_size;
            if ((dst_buf_size) && (!(*pPut_buf_func)(pDict + dict_ofs, (int)dst_buf_size, pPut_buf_user)))
                break;
            if (status != TINFL_STATUS_HAS_MORE_OUTPUT)
            {
                result = (status == TINFL_STATUS_DONE);
                break;
            }
            dict_ofs = (dict_ofs + dst_buf_size) & (TINFL_LZ_DICT_SIZE - 1);
        }
        MZ_FREE(pDict);
        *pIn_buf_size = in_buf_ofs;
        return result;
    }

#ifndef MINIZ_NO_MALLOC
    tinfl_decompressor *tinfl_decompressor_alloc(void)
    {
        tinfl_decompressor *pDecomp = (tinfl_decompressor *)MZ_MALLOC(sizeof(tinfl_decompressor));
        if (pDecomp)
            tinfl_init(pDecomp);
        return pDecomp;
    }

    void tinfl_decompressor_free(tinfl_decompressor *pDecomp)
    {
        MZ_FREE(pDecomp);
    }
#endif /* MINIZ_NO_MALLOC */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* MINIZ_NO_INFLATE_APIS */
)WTCBUNDLE";
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
        o << "namespace tinfl {\n";
        o << TINFL_BUNDLE;
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
                o << "    // gzip: 10B header + raw deflate + 8B tail\n";
                o << "    if (gz.size() < 20) { res.set_content(\"bad gzip\", \"text/plain\"); return; }\n";
                o << "    const unsigned char* gp = reinterpret_cast<const unsigned char*>(gz.data());\n";
                o << "    unsigned int flg = gp[3];\n";
                o << "    std::size_t hdr = 10;\n";
                o << "    if (flg & 0x04) { hdr += 2 + (unsigned int)(gp[hdr] | (gp[hdr+1] << 8)); }\n";
                o << "    if (flg & 0x08) { while (hdr < gz.size() && gz[hdr] != 0) ++hdr; ++hdr; }\n";
                o << "    if (flg & 0x10) { while (hdr < gz.size() && gz[hdr] != 0) ++hdr; ++hdr; }\n";
                o << "    if (flg & 0x02) hdr += 2;\n";
                o << "    const void* src = gp + hdr;\n";
                o << "    size_t src_len = gz.size() - hdr - 8;\n";
                o << "    std::vector<unsigned char> out_buf(1024 * 1024);\n";
                o << "    size_t n = tinfl::tinfl_decompress_mem_to_mem(out_buf.data(), out_buf.size(), src, src_len, TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);\n";
                o << "    if (n == TINFL_DECOMPRESS_MEM_TO_MEM_FAILED) { res.set_content(\"inflate error\", \"text/plain\"); return; }\n";
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
