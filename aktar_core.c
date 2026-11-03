// Norovox Aktar — C veri düzlemi: internetsiz doğrudan kablo (25GbE / USB4-TB ağı) üzerinden çok akışlı dosya aktarımı.
// Her parça: pread → (zstd-1, yalnız küçülüyorsa) → AES-256-GCM (AES-NI) → TCP; alıcı: doğrula (GCM etiketi + BLAKE3) → pwrite.
// Python tavanını (v0.1: 1,0-1,4 GB/s loopback) kaldırmak için: iş parçacığı başına bir bağlantı, kopyasız tamponlar, OpenSSL EVP.
//
// derleme: gcc -O3 -march=native -pthread aktar_core.c blake3/*.c -lssl -lcrypto -lzstd -o aktar_core
// gönder : aktar_core send <host> <port> <streams> <key_hex64> <dosya>
// al     : aktar_core recv <port> <streams> <key_hex64> <çıktı>
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <zstd.h>
#include "blake3/blake3.h"

#define CHUNK (8u << 20)
#define MAGIC 0x52544B41u                                 // "AKTR"

typedef struct __attribute__((packed)) {
    uint32_t magic, flags;                                // flags bit0 = zstd
    uint64_t off, raw_len, wire_len, total;
    uint8_t salt[16], iv[12], tag[16], hash[32];          // salt: aktarım başına rastgele; hash = BLAKE3(ham parça)
} hdr_t;

static uint8_t MASTER[32], KEY[32], SALT[16];             // KEY = BLAKE3-keyed(MASTER, SALT): her aktarım yeni oturum anahtarı
static const char *PATH;
static int FD, PORT_N, STREAMS;
static uint64_t TOTAL;
static _Atomic uint64_t NEXT, DONE_BYTES, WIRE_BYTES, ZCHUNKS;

static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec * 1e-9; }
static void die(const char *m) { perror(m); exit(1); }

static int full_io(int fd, void *buf, size_t n, int wr) {
    uint8_t *p = buf;
    while (n) {
        ssize_t k = wr ? send(fd, p, n, MSG_NOSIGNAL) : recv(fd, p, n, MSG_WAITALL);
        if (k <= 0) { if (k < 0 && errno == EINTR) continue; return -1; }
        p += k; n -= (size_t)k;
    }
    return 0;
}

static void derive(void) {
    blake3_hasher bh; blake3_hasher_init_keyed(&bh, MASTER); blake3_hasher_update(&bh, "aktar-oturum-v1", 15);
    blake3_hasher_update(&bh, SALT, 16); blake3_hasher_finalize(&bh, KEY, 32);
}

static void tune(int s) {
    int one = 1, buf = 16 << 20;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buf, sizeof buf);
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &buf, sizeof buf);
}

static int gcm(int enc, const uint8_t *iv, const uint8_t *in, int n, uint8_t *out, uint8_t *tag) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new(); int l = 0, ok = 1;
    if (enc) {
        ok &= EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, KEY, iv);
        ok &= EVP_EncryptUpdate(c, out, &l, in, n); ok &= EVP_EncryptFinal_ex(c, out + l, &l);
        ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, tag);
    } else {
        ok &= EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, KEY, iv);
        ok &= EVP_DecryptUpdate(c, out, &l, in, n);
        ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, tag);
        ok &= EVP_DecryptFinal_ex(c, out + l, &l) > 0;    // etiket tutmazsa 0
    }
    EVP_CIPHER_CTX_free(c);
    return ok ? 0 : -1;
}

typedef struct { const char *host; int port; } conn_t;

static void *sender(void *arg) {
    conn_t *ct = arg;
    int s = socket(AF_INET, SOCK_STREAM, 0); tune(s);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(ct->port)};
    inet_pton(AF_INET, ct->host, &a.sin_addr);
    for (int t = 0; connect(s, (void *)&a, sizeof a) < 0; t++) { if (t > 200) die("connect"); usleep(50000); }
    uint8_t *raw = malloc(CHUNK), *z = malloc(ZSTD_compressBound(CHUNK)), *ct_buf = malloc(ZSTD_compressBound(CHUNK));
    ZSTD_CCtx *zc = ZSTD_createCCtx();
    int zmode = getenv("AKTAR_ZSTD") ? atoi(getenv("AKTAR_ZSTD")) : 1;   // 0 = kapalı
    for (;;) {
        uint64_t idx = atomic_fetch_add(&NEXT, 1), off = idx * CHUNK;
        hdr_t h = {.magic = MAGIC, .total = TOTAL};
        memcpy(h.salt, SALT, 16);
        if (off >= TOTAL) { h.flags = 0xFFFFFFFF; full_io(s, &h, sizeof h, 1); break; }   // akış sonu
        size_t n = TOTAL - off < CHUNK ? TOTAL - off : CHUNK, got = 0;
        while (got < n) { ssize_t k = pread(FD, raw + got, n - got, off + got); if (k <= 0) die("pread"); got += k; }
        blake3_hasher bh; blake3_hasher_init(&bh); blake3_hasher_update(&bh, raw, n); blake3_hasher_finalize(&bh, h.hash, 32);
        const uint8_t *pay = raw; size_t pl = n;
        if (zmode) {
            size_t zl = ZSTD_compressCCtx(zc, z, ZSTD_compressBound(n), raw, n, zmode);
            if (!ZSTD_isError(zl) && zl < n - n / 16) { pay = z; pl = zl; h.flags |= 1; atomic_fetch_add(&ZCHUNKS, 1); }
        }
        memcpy(h.iv, &idx, 8); memcpy(h.iv + 8, &h.magic, 4);           // IV = parça no (anahtar başına tekil)
        if (gcm(1, h.iv, pay, (int)pl, ct_buf, h.tag)) die("gcm");
        h.off = off; h.raw_len = n; h.wire_len = pl;
        if (full_io(s, &h, sizeof h, 1) || full_io(s, ct_buf, pl, 1)) die("send");
        atomic_fetch_add(&DONE_BYTES, n); atomic_fetch_add(&WIRE_BYTES, pl + sizeof h);
    }
    uint8_t ack; recv(s, &ack, 1, MSG_WAITALL);                          // alıcı yazmayı bitirdi
    close(s); free(raw); free(z); free(ct_buf); ZSTD_freeCCtx(zc);
    return NULL;
}

static _Atomic int BAD;
static int DISCARD;

static void *receiver(void *arg) {
    int s = (int)(intptr_t)arg;
    uint8_t *w = malloc(ZSTD_compressBound(CHUNK)), *pt = malloc(ZSTD_compressBound(CHUNK)), *raw = malloc(CHUNK);
    ZSTD_DCtx *zd = ZSTD_createDCtx();
    for (;;) {
        hdr_t h;
        if (full_io(s, &h, sizeof h, 0) || h.magic != MAGIC) die("hdr");
        if (h.flags == 0xFFFFFFFF) break;
        if (FD < 0) {                                                     // ilk parça: çıktı boyu belli
            static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
            pthread_mutex_lock(&mu);
            if (FD < 0) { memcpy(SALT, h.salt, 16); derive();
                          int fd = open(PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644); if (fd < 0 || ftruncate(fd, h.total)) die("open"); TOTAL = h.total; FD = fd; }
            pthread_mutex_unlock(&mu);
        }
        if (memcmp(h.salt, SALT, 16)) die("salt");
        if (h.wire_len > ZSTD_compressBound(CHUNK) || h.raw_len > CHUNK) die("len");
        if (full_io(s, w, h.wire_len, 0)) die("recv");
        if (gcm(0, h.iv, w, (int)h.wire_len, pt, h.tag)) { atomic_store(&BAD, 1); die("gcm etiketi tutmadi"); }
        const uint8_t *data = pt;
        if (h.flags & 1) {
            size_t r = ZSTD_decompressDCtx(zd, raw, CHUNK, pt, h.wire_len);
            if (ZSTD_isError(r) || r != h.raw_len) die("zstd");
            data = raw;
        }
        uint8_t hh[32]; blake3_hasher bh; blake3_hasher_init(&bh); blake3_hasher_update(&bh, data, h.raw_len); blake3_hasher_finalize(&bh, hh, 32);
        if (memcmp(hh, h.hash, 32)) { atomic_store(&BAD, 1); die("blake3 tutmadi"); }
        size_t put = DISCARD ? h.raw_len : 0;                  // AKTAR_DISCARD=1: doğrula ama yazma (çekirdek hız ölçümü)
        while (put < h.raw_len) { ssize_t k = pwrite(FD, data + put, h.raw_len - put, h.off + put); if (k <= 0) die("pwrite"); put += k; }
        atomic_fetch_add(&DONE_BYTES, h.raw_len);
    }
    uint8_t ack = 1; full_io(s, &ack, 1, 1);
    close(s); free(w); free(pt); free(raw); ZSTD_freeDCtx(zd);
    return NULL;
}

static void parse_key(const char *hex) {
    if (strlen(hex) != 64) { fprintf(stderr, "anahtar 64 hex olmalı\n"); exit(2); }
    for (int i = 0; i < 32; i++) sscanf(hex + 2 * i, "%2hhx", &MASTER[i]);
}

int main(int argc, char **argv) {
    if (argc >= 7 && !strcmp(argv[1], "send")) {
        STREAMS = atoi(argv[4]); parse_key(argv[5]); PATH = argv[6];
        FD = open(PATH, O_RDONLY); if (FD < 0) die("open");
        int ur = open("/dev/urandom", O_RDONLY); if (ur < 0 || read(ur, SALT, 16) != 16) die("urandom"); close(ur); derive();
        struct stat st; fstat(FD, &st); TOTAL = st.st_size;
        conn_t ct = {argv[2], atoi(argv[3])};
        pthread_t th[256]; double t0 = now();
        for (int i = 0; i < STREAMS; i++) pthread_create(&th[i], NULL, sender, &ct);
        for (int i = 0; i < STREAMS; i++) pthread_join(th[i], NULL);
        double dt = now() - t0;
        printf("{\"rol\":\"gonder\",\"bayt\":%llu,\"sn\":%.3f,\"GBs\":%.3f,\"kablo_bayt\":%llu,\"zstd_parca\":%llu,\"akis\":%d}\n",
               (unsigned long long)TOTAL, dt, TOTAL / 1e9 / dt, (unsigned long long)WIRE_BYTES, (unsigned long long)ZCHUNKS, STREAMS);
        return 0;
    }
    if (argc >= 6 && !strcmp(argv[1], "recv")) {
        DISCARD = getenv("AKTAR_DISCARD") && atoi(getenv("AKTAR_DISCARD"));
        PORT_N = atoi(argv[2]); STREAMS = atoi(argv[3]); parse_key(argv[4]); PATH = argv[5]; FD = -1;
        int ls = socket(AF_INET, SOCK_STREAM, 0), one = 1;
        setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
        struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(PORT_N), .sin_addr.s_addr = INADDR_ANY};
        if (bind(ls, (void *)&a, sizeof a) || listen(ls, 256)) die("listen");
        pthread_t th[256]; double t0 = 0;
        for (int i = 0; i < STREAMS; i++) {
            int s = accept(ls, NULL, NULL); if (s < 0) die("accept"); tune(s);
            if (!i) t0 = now();
            pthread_create(&th[i], NULL, receiver, (void *)(intptr_t)s);
        }
        for (int i = 0; i < STREAMS; i++) pthread_join(th[i], NULL);
        if (FD < 0) { FD = open(PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644); if (FD < 0) die("open"); }   // boş dosya
        fsync(FD); close(FD);
        double dt = now() - t0;
        printf("{\"rol\":\"al\",\"bayt\":%llu,\"sn\":%.3f,\"GBs\":%.3f,\"bozuk\":%d}\n",
               (unsigned long long)DONE_BYTES, dt, DONE_BYTES / 1e9 / dt, (int)BAD);
        return BAD;
    }
    fprintf(stderr, "kullanım: aktar_core send <host> <port> <akis> <anahtar_hex64> <dosya>\n"
                    "          aktar_core recv <port> <akis> <anahtar_hex64> <cikti>\n");
    return 2;
}
