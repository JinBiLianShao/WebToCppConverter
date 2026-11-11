/**
 * tinf - tiny inflate library (DEFLATE/zlib/gzip decompressor)
 * Based on Joergen Ibsen's tinf (public domain)
 * https://github.com/jibsen/tinf
 *
 * 本文件是裁剪适配版：只保留 gzip raw inflate 解压能力。
 */
#ifndef TINF_H
#define TINF_H

#ifdef __cplusplus
extern "C" {
#endif

#define TINF_OK             0
#define TINF_DATA_ERROR    (-3)
#define TINF_BUF_ERROR     (-5)

typedef struct {
    unsigned char *dest;
    unsigned int destLen;
} tinf_data;

#ifdef __cplusplus
}
#endif

#endif // TINF_H
