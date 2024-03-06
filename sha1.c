#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ROTLEFT(a, b) ((a << b) | (a >> (32 - b)))
#define SHA1_BLOCK_SIZE 20

typedef unsigned char BYTE;
typedef unsigned int WORD;

typedef struct
{
    BYTE data[64];
    WORD datalen;
    unsigned long long bitlen;
    WORD state[5];
    WORD k[4];
} SHA1_CTX;

void sha1_transform(SHA1_CTX *ctx, const BYTE data[]);
void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, const BYTE data[], size_t len);
void sha1_final(SHA1_CTX *ctx, BYTE hash[]);
int sha1_test();

void sha1_transform(SHA1_CTX *ctx, const BYTE data[])
{
    WORD a, b, c, d, e, i, j, t, m[80];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) + (data[j + 1] << 16) + (data[j + 2] << 8) + (data[j + 3]);
    for (; i < 80; ++i)
    {
        m[i] = (m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16]);
        m[i] = (m[i] << 1) | (m[i] >> 31);
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    for (i = 0; i < 20; ++i)
    {
        t = ROTLEFT(a, 5) + ((b & c) ^ (~b & d)) + e + ctx->k[0] + m[i];
        e = d;
        d = c;
        c = ROTLEFT(b, 30);
        b = a;
        a = t;
    }
    for (; i < 40; ++i)
    {
        t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[1] + m[i];
        e = d;
        d = c;
        c = ROTLEFT(b, 30);
        b = a;
        a = t;
    }
    for (; i < 60; ++i)
    {
        t = ROTLEFT(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + ctx->k[2] + m[i];
        e = d;
        d = c;
        c = ROTLEFT(b, 30);
        b = a;
        a = t;
    }
    for (; i < 80; ++i)
    {
        t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[3] + m[i];
        e = d;
        d = c;
        c = ROTLEFT(b, 30);
        b = a;
        a = t;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

void sha1_init(SHA1_CTX *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xc3d2e1f0;
    ctx->k[0] = 0x5a827999;
    ctx->k[1] = 0x6ed9eba1;
    ctx->k[2] = 0x8f1bbcdc;
    ctx->k[3] = 0xca62c1d6;
}

void sha1_update(SHA1_CTX *ctx, const BYTE data[], size_t len)
{
    size_t i;

    for (i = 0; i < len; ++i)
    {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64)
        {
            sha1_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha1_final(SHA1_CTX *ctx, BYTE hash[])
{
    WORD i;

    i = ctx->datalen;

    if (ctx->datalen < 56)
    {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    }
    else
    {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha1_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha1_transform(ctx, ctx->data);

    for (i = 0; i < 4; ++i)
    {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
    }
}

int sha1_test()
{
    BYTE text1[] = {"abc"};
    BYTE text2[] = {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
    BYTE text3[] = {"aaaaaaaaaa"};
    BYTE hash1[SHA1_BLOCK_SIZE] = {0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d};
    BYTE hash2[SHA1_BLOCK_SIZE] = {0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1};
    // BYTE hash3[SHA1_BLOCK_SIZE] = {0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 0xeb, 0x2b, 0xdb, 0xad, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6f};
    BYTE buf[SHA1_BLOCK_SIZE];
    int idx;
    SHA1_CTX ctx;
    int pass = 1;
    clock_t start, end;
    double cpu_time_used;

    start = clock();
    sha1_init(&ctx);
    sha1_update(&ctx, text1, strlen(text1));
    sha1_final(&ctx, buf);
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("SHA-256 MAC for message size %zu bytes: %.6f seconds\n", strlen(text1), cpu_time_used);

    pass = pass && !memcmp(hash1, buf, SHA1_BLOCK_SIZE);

    start = clock();
    sha1_init(&ctx);
    sha1_update(&ctx, text2, strlen(text2));
    sha1_final(&ctx, buf);
    end = clock();

    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("SHA-256 MAC for message size %zu bytes: %.6f seconds\n", strlen(text2), cpu_time_used);
    pass = pass && !memcmp(hash2, buf, SHA1_BLOCK_SIZE);

    start = clock();
    sha1_init(&ctx);
    for (idx = 0; idx < 10000000; ++idx)
        sha1_update(&ctx, text3, strlen(text3));
    sha1_final(&ctx, buf);
    end = clock();

    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("SHA-256 MAC for message size %zu bytes: %.6f seconds\n", strlen(text3) * 10000000, cpu_time_used);
    // pass = pass && !memcmp(hash3, buf, SHA1_BLOCK_SIZE);

    printf("SHA1 hash of 'abc': ");
    for (int i = 0; i < SHA1_BLOCK_SIZE; ++i)
    {
        printf("%02x", hash1[i]);
    }
    printf("\n");

    printf("SHA1 hash of 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq': ");
    for (int i = 0; i < SHA1_BLOCK_SIZE; ++i)
    {
        printf("%02x", hash2[i]);
    }
    printf("\n");

    printf("SHA1 hash of 'aaaaaaaaaa' (repeated 1,00,00,000 times): ");
    for (int i = 0; i < SHA1_BLOCK_SIZE; ++i)
    {
        printf("%02x", buf[i]);
    }
    printf("\n");

    return (pass);
}

int main()
{
    printf("SHA1 tests: %s\n", sha1_test() ? "SUCCEEDED" : "FAILED");

    return (0);
}
