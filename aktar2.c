// Norovox Aktar v2 — internetsiz doğrudan kablo üzerinden klasör/dosya aktarımı (veri düzlemi).
// Küçük dosyalar 8 MiB parçalara toplanır; parça başına (uyarlanır zstd-1) → AES-256-GCM → TCP; alıcı doğrular → pwrite.
// v1'e göre: başlık GCM AAD ile bağlı (parça yer değiştirilemez), alıcı nonce'u (oturum yeniden oynatılamaz), iki yönlü anahtar kanıtı,
// parça bit haritası (eksik/çift parça hata), kaldığı yerden devam, klasör ağacı, yol denetimi, anahtar komut satırında değil.
//
// derleme: gcc -O3 -march=native -pthread aktar2.c blake3/*.o -lssl -lcrypto -lzstd -o aktar2
// anahtar: AKTAR_KEY ortam değişkeni (64 hex)
// gönder : aktar2 send <host> <port> <akis> <dosya|klasör>
// al     : aktar2 recv <port> <cikti_klasoru>
// isteğe bağlı: AKTAR_ZSTD=-1 uyarlanır (varsayılan), 0 kapalı, 1 açık; AKTAR_LIMIT_MBS=N bağlantı hızı benzetimi
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <stddef.h>
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
#include <utime.h>
#include <zstd.h>
#include "blake3/blake3.h"

#define CHUNK (8u << 20)
#define PROBE (256u << 10)
#define MAGIC 0x32544B41u                                 // "AKT2"
#define F_ZSTD 1u
#define F_END 0x80000000u
#define MAKS_MANIFEST (1ull << 30)
#define STATE ".aktar-state"

typedef struct __attribute__((packed)) { uint32_t magic, flags; uint64_t idx; uint32_t raw_len, wire_len; uint8_t tag[16]; } hdr_t;
typedef struct __attribute__((packed)) { uint32_t magic, streams; uint8_t salt[16]; uint64_t total, mlen; uint32_t chunk; uint8_t tag[16]; } hello_t;
typedef struct { uint8_t type; uint32_t mode; int64_t mtime; uint64_t size, voff, ino; uint32_t sira; char *name; } ent_t;     // type: 0 dosya, 1 klasör
typedef struct { int idx, fd, dfd; size_t dl; char dir[PATH_MAX]; } fdc_t;               // dfd: son kullanılan klasör, yol çözümünü kısaltır
#define FDC_BOS {.idx = -1, .fd = -1, .dfd = -1}
#define MIN_CH (256u << 10)
#define TEK(e) ((e)->voff / CH == ((e)->voff + (e)->size - 1) / CH)      // dosyanın tamamı tek parçanın içinde: dört sistem çağrısıyla yazılır

static uint8_t MASTER[32], KEY[32], SALT[16], RNONCE[16], MHASH[32];
static const char *BASE;                                  // gönderende kökün üst klasörü, alıcıda çıktı klasörü
static ent_t *E; static size_t NE;
static ent_t **FI; static size_t NF;                      // boyu >0 dosyalar, voff sıralı
static uint64_t TOTAL, NCHUNK, ATLANAN_BAG;
static uint32_t CH;                                       // oturumun parça boyu; küçük dosyalı ağaçta küçülür ki iş akışlara eşit dağılsın
static _Atomic uint64_t NEXT, DONE_BYTES, WIRE_BYTES, ZCHUNKS;
static _Atomic uint8_t *BITS;
static double LIMIT;                                      // akış başına bayt/sn; 0 = sınırsız
static int STREAMS, BITTI;
static const char *CTXT = "aktar-oturum-v2";

static double now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + t.tv_nsec * 1e-9; }
static void die(const char *m) { fprintf(stderr, "HATA %s: %s\n", m, strerror(errno)); exit(1); }
static void die2(const char *m) { fprintf(stderr, "HATA %s\n", m); exit(1); }

static int full_io(int fd, void *buf, size_t n, int wr, int more) {
    uint8_t *p = buf;
    while (n) {
        ssize_t k = wr ? send(fd, p, n, MSG_NOSIGNAL | (more ? MSG_MORE : 0)) : recv(fd, p, n, MSG_WAITALL);
        if (k <= 0) { if (k < 0 && errno == EINTR) continue; return -1; }
        p += k; n -= (size_t)k;
    }
    return 0;
}

static void derive(void) {
    blake3_hasher b; blake3_hasher_init_keyed(&b, MASTER); blake3_hasher_update(&b, CTXT, strlen(CTXT));
    blake3_hasher_update(&b, SALT, 16); blake3_hasher_update(&b, RNONCE, 16); blake3_hasher_finalize(&b, KEY, 32);
}

static void tune(int s) {
    int one = 1, buf = 16 << 20;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &buf, sizeof buf);
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &buf, sizeof buf);
}

// Yerinde şifreleme. IV: 4 bayt alan + 8 bayt sayaç; anahtar oturum başına tekil olduğundan IV tekrar etmez.
static int gcm(EVP_CIPHER_CTX *c, int enc, uint32_t alan, uint64_t ctr, const void *aad, int alen, uint8_t *buf, int n, uint8_t *tag) {
    uint8_t iv[12]; int l = 0, ok = 1; memcpy(iv, &alan, 4); memcpy(iv + 4, &ctr, 8);
    if (enc) {
        ok &= EVP_EncryptInit_ex(c, NULL, NULL, NULL, iv);
        if (alen) ok &= EVP_EncryptUpdate(c, NULL, &l, aad, alen);
        if (n) ok &= EVP_EncryptUpdate(c, buf, &l, buf, n);
        ok &= EVP_EncryptFinal_ex(c, buf + (n ? l : 0), &l);
        ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, tag);
    } else {
        ok &= EVP_DecryptInit_ex(c, NULL, NULL, NULL, iv);
        if (alen) ok &= EVP_DecryptUpdate(c, NULL, &l, aad, alen);
        if (n) ok &= EVP_DecryptUpdate(c, buf, &l, buf, n);
        ok &= EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, tag);
        ok &= EVP_DecryptFinal_ex(c, buf + (n ? l : 0), &l) > 0;
    }
    return ok ? 0 : -1;
}

static EVP_CIPHER_CTX *ctx_yeni(int enc) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (enc ? !EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, KEY, NULL) : !EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, KEY, NULL)) die2("gcm baslat");
    return c;
}

static void yol(char *out, size_t n, const char *name) { if (snprintf(out, n, "%s/%s", BASE, name) >= (int)n) die2("yol cok uzun"); }

// Sanal akış (tüm dosyaların art arda dizilişi) üzerinde okuma/yazma; açık dosya iş parçacığı başına önbellekte.
static int dizin_fd(fdc_t *fc, const char *name, const char **yaprak) {
    const char *s = strrchr(name, '/'); size_t dl = s ? (size_t)(s - name) : 0;
    *yaprak = s ? s + 1 : name;
    if (fc->dfd >= 0 && fc->dl == dl && !memcmp(fc->dir, name, dl)) return fc->dfd;
    if (fc->dfd >= 0) close(fc->dfd);
    if (dl >= sizeof fc->dir) die2("yol cok uzun");
    char p[PATH_MAX]; memcpy(fc->dir, name, dl); fc->dir[dl] = 0; fc->dl = dl;
    if (snprintf(p, sizeof p, "%s/%s", BASE, fc->dir) >= (int)sizeof p) die2("yol cok uzun");
    fc->dfd = open(p, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fc->dfd < 0) die(p);
    return fc->dfd;
}

static void tek_yaz(fdc_t *fc, ent_t *e, const uint8_t *buf) {
    const char *y; int d = dizin_fd(fc, e->name, &y), m = (int)(e->mode & 0777);     // setuid/setgid taşınmaz
    int fd = openat(d, y, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, m);
    if (fd < 0 && errno == EEXIST) {                         // yeniden aktarım: eski dosyanın kipi korunmasın
        fd = openat(d, y, O_WRONLY | O_TRUNC | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0 && errno == EACCES) { unlinkat(d, y, 0); fd = openat(d, y, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, m); }
        else if (fd >= 0) fchmod(fd, (mode_t)m);
    }
    if (fd < 0) die(e->name);
    for (size_t g = 0; g < e->size;) {
        ssize_t r = write(fd, buf + g, e->size - g);
        if (r <= 0) die("write");
        g += (size_t)r;
    }
    struct timespec t[2] = {{e->mtime, 0}, {e->mtime, 0}}; futimens(fd, t); close(fd);
}

static void tek_oku(fdc_t *fc, ent_t *e, uint8_t *buf) {
    const char *y; int d = dizin_fd(fc, e->name, &y), fd = openat(d, y, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) die(e->name);
    for (size_t g = 0; g < e->size;) {
        ssize_t r = read(fd, buf + g, e->size - g);
        if (r <= 0) die("read (dosya aktarim sirasinda degisti mi?)");
        g += (size_t)r;
    }
    close(fd);
}

static void vio(int wr, fdc_t *fc, uint8_t *buf, uint64_t off, size_t n) {
    size_t lo = 0, hi = NF;
    while (hi - lo > 1) { size_t m = (lo + hi) / 2; if (FI[m]->voff <= off) lo = m; else hi = m; }
    for (size_t i = lo; n; i++) {
        if (i >= NF) die2("sanal akis tasti");
        ent_t *e = FI[i]; uint64_t ic = off - e->voff; size_t k = e->size - ic < n ? (size_t)(e->size - ic) : n;
        if (TEK(e)) {
            if (wr) tek_yaz(fc, e, buf); else tek_oku(fc, e, buf);
            buf += k; off += k; n -= k;
            continue;
        }
        if (fc->idx != (int)i) {
            if (fc->fd >= 0) close(fc->fd);
            char p[PATH_MAX]; yol(p, sizeof p, e->name);
            fc->fd = open(p, wr ? O_WRONLY | O_NOFOLLOW : O_RDONLY); fc->idx = (int)i;
            if (fc->fd < 0) die(p);
        }
        size_t g = 0;
        while (g < k) {
            ssize_t r = wr ? pwrite(fc->fd, buf + g, k - g, ic + g) : pread(fc->fd, buf + g, k - g, ic + g);
            if (r <= 0) die(wr ? "pwrite" : "pread (dosya aktarim sirasinda degisti mi?)");
            g += r;
        }
        buf += k; off += k; n -= k;
    }
}

static size_t raw_of(uint64_t idx) { uint64_t o = idx * CH; return TOTAL - o < CH ? (size_t)(TOTAL - o) : CH; }

typedef struct { const char *host; int port; } conn_t;

static int baglan(const char *host, int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0); tune(s);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1) die2("adres");
    for (int t = 0; connect(s, (void *)&a, sizeof a) < 0; t++) { if (t > 200) die("connect"); usleep(50000); }
    return s;
}

static void *sender(void *arg) {
    conn_t *ct = arg; int s = baglan(ct->host, ct->port); uint8_t rn[16];
    if (full_io(s, rn, 16, 0, 0)) die("nonce");
    uint8_t *raw = malloc(CHUNK + 64), *z = malloc(ZSTD_compressBound(CHUNK)); ZSTD_CCtx *zc = ZSTD_createCCtx();
    EVP_CIPHER_CTX *c = ctx_yeni(1); fdc_t fc = FDC_BOS;
    int zmode = getenv("AKTAR_ZSTD") ? atoi(getenv("AKTAR_ZSTD")) : -1, kullan = 0;
    double ts = 0, tz = 0, r = 1, t_lim = now(); uint64_t gonderilen = 0, say = 0;
    for (;;) {
        uint64_t idx = atomic_fetch_add(&NEXT, 1);
        if (idx >= NCHUNK) break;
        if (atomic_load(&BITS[idx / 8]) >> (idx % 8) & 1) continue;      // kaldığı yerden devam
        size_t n = raw_of(idx); vio(0, &fc, raw, idx * CH, n);
        hdr_t h = {.magic = MAGIC, .idx = idx, .raw_len = (uint32_t)n};
        uint8_t *pay = raw; size_t pl = n;
        if (zmode < 0 && say++ % 16 == 0 && n >= PROBE) {                // karar yalnız parçanın başından alınan örnekle: hızlı hatta maliyeti yok denecek kadar az
            double t = now(); size_t zl = ZSTD_compressCCtx(zc, z, ZSTD_compressBound(PROBE), raw, PROBE, 1); t = now() - t;
            if (!ZSTD_isError(zl)) {
                tz = t / PROBE; r = (double)zl / PROBE;
                kullan = ts > 0 && tz + r * ts < 0.95 * ts;              // sıkıştırma + küçük gönderim, ham gönderimden hızlı mı
            }
        }
        if (zmode > 0 || (zmode < 0 && kullan)) {
            size_t zl = ZSTD_compressCCtx(zc, z, ZSTD_compressBound(n), raw, n, 1);
            if (!ZSTD_isError(zl) && zl < n - n / 16) { pay = z; pl = zl; h.flags |= F_ZSTD; atomic_fetch_add(&ZCHUNKS, 1); }
        }
        h.wire_len = (uint32_t)pl;
        if (gcm(c, 1, 1, idx, &h, offsetof(hdr_t, tag), pay, (int)pl, h.tag)) die2("gcm");
        double t = now();
        if (full_io(s, &h, sizeof h, 1, 1) || full_io(s, pay, pl, 1, 0)) die("send");
        gonderilen += pl + sizeof h;
        if (LIMIT > 0) { double k = t_lim + gonderilen / LIMIT - now(); if (k > 0) usleep((useconds_t)(k * 1e6)); }
        double b = (now() - t) / (pl + sizeof h); ts = ts > 0 ? 0.8 * ts + 0.2 * b : b;
        atomic_fetch_add(&DONE_BYTES, n); atomic_fetch_add(&WIRE_BYTES, pl + sizeof h);
    }
    hdr_t h = {.magic = MAGIC, .flags = F_END}; full_io(s, &h, sizeof h, 1, 0);
    uint8_t ack; recv(s, &ack, 1, MSG_WAITALL);
    if (fc.fd >= 0) close(fc.fd);
    if (fc.dfd >= 0) close(fc.dfd);
    close(s); free(raw); free(z); ZSTD_freeCCtx(zc); EVP_CIPHER_CTX_free(c);
    return NULL;
}

static void *receiver(void *arg) {
    int s = (int)(intptr_t)arg;
    uint8_t *w = malloc(ZSTD_compressBound(CHUNK) + 64), *raw = malloc(CHUNK); ZSTD_DCtx *zd = ZSTD_createDCtx();
    EVP_CIPHER_CTX *c = ctx_yeni(0); fdc_t fc = FDC_BOS;
    for (;;) {
        hdr_t h;
        if (full_io(s, &h, sizeof h, 0, 0)) die("baslik");
        if (h.magic != MAGIC) die2("baslik bozuk");
        if (h.flags == F_END) break;
        if (h.idx >= NCHUNK || h.raw_len != raw_of(h.idx) || h.wire_len > ZSTD_compressBound(CHUNK)) die2("gecersiz parca baslgi");
        if (full_io(s, w, h.wire_len, 0, 0)) die("veri");
        if (gcm(c, 0, 1, h.idx, &h, offsetof(hdr_t, tag), w, (int)h.wire_len, h.tag)) die2("GCM etiketi tutmadi: veri veya baslik degismis");
        const uint8_t *d = w;
        if (h.flags & F_ZSTD) {
            size_t r = ZSTD_decompressDCtx(zd, raw, CHUNK, w, h.wire_len);
            if (ZSTD_isError(r) || r != h.raw_len) die2("zstd");
            d = raw;
        } else if (h.wire_len != h.raw_len) die2("boy tutmadi");
        vio(1, &fc, (uint8_t *)d, h.idx * CH, h.raw_len);
        uint8_t m = (uint8_t)(1u << (h.idx % 8));
        if (atomic_fetch_or(&BITS[h.idx / 8], m) & m) die2("cift parca");
        atomic_fetch_add(&DONE_BYTES, h.raw_len);
    }
    uint8_t ack = 1; full_io(s, &ack, 1, 1, 0);
    if (fc.fd >= 0) close(fc.fd);
    if (fc.dfd >= 0) close(fc.dfd);
    close(s); free(w); free(raw); ZSTD_freeDCtx(zd); EVP_CIPHER_CTX_free(c);
    return NULL;
}

static void parse_key(void) {
    const char *hex = getenv("AKTAR_KEY");
    if (!hex || strlen(hex) != 64) die2("AKTAR_KEY 64 hex olmali");
    for (int i = 0; i < 32; i++) if (sscanf(hex + 2 * i, "%2hhx", &MASTER[i]) != 1) die2("AKTAR_KEY hex degil");
}

static size_t CAP_E; static size_t KOK_LEN;

static pthread_mutex_t G_M = PTHREAD_MUTEX_INITIALIZER; static pthread_cond_t G_C = PTHREAD_COND_INITIALIZER;
typedef struct gez_d { char *yol; struct gez_d *sonraki; } gez_d;
static gez_d *G_Y; static int G_AKTIF;

static void ekle(char *ad, const struct stat *st, int type) {          // ad sahipliği buraya geçer
    uint32_t derin = 0; for (const char *p = ad; *p; p++) derin += *p == '/';
    ent_t e = {.type = (uint8_t)type, .mode = st->st_mode & 07777, .mtime = st->st_mtime, .size = type ? 0 : (uint64_t)st->st_size, .ino = (uint64_t)st->st_ino, .sira = derin, .name = ad};
    pthread_mutex_lock(&G_M);
    if (NE == CAP_E) { CAP_E = CAP_E ? CAP_E * 2 : 1024; E = realloc(E, CAP_E * sizeof *E); }
    E[NE++] = e;
    pthread_mutex_unlock(&G_M);
}

static void gez_ekle(char *yol) {
    gez_d *n = malloc(sizeof *n); n->yol = yol;
    pthread_mutex_lock(&G_M); n->sonraki = G_Y; G_Y = n; pthread_cond_signal(&G_C); pthread_mutex_unlock(&G_M);
}

static void atla_say(void) { pthread_mutex_lock(&G_M); ATLANAN_BAG++; pthread_mutex_unlock(&G_M); }   // sembolik bağ, soket vb. aktarılmaz, sayısı raporlanır

static void gez_klasor(const char *yol) {
    int d = open(yol, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (d < 0) { atla_say(); return; }
    DIR *D = fdopendir(d); if (!D) die(yol);
    size_t yl = strlen(yol); struct dirent *g;
    while ((g = readdir(D))) {
        if (g->d_name[0] == '.' && (!g->d_name[1] || (g->d_name[1] == '.' && !g->d_name[2]))) continue;
        if (g->d_type != DT_UNKNOWN && g->d_type != DT_REG && g->d_type != DT_DIR) { atla_say(); continue; }
        struct stat st;
        if (fstatat(d, g->d_name, &st, AT_SYMLINK_NOFOLLOW)) { atla_say(); continue; }
        if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) { atla_say(); continue; }
        size_t nl = strlen(g->d_name); char *p = malloc(yl + nl + 2);
        memcpy(p, yol, yl); p[yl] = '/'; memcpy(p + yl + 1, g->d_name, nl + 1);
        ekle(strdup(p + KOK_LEN), &st, S_ISDIR(st.st_mode));
        if (S_ISDIR(st.st_mode)) gez_ekle(p); else free(p);
    }
    closedir(D);
}

static void *gez_is(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&G_M);
        while (!G_Y && G_AKTIF) pthread_cond_wait(&G_C, &G_M);
        if (!G_Y) { pthread_cond_broadcast(&G_C); pthread_mutex_unlock(&G_M); return NULL; }
        gez_d *n = G_Y; G_Y = n->sonraki; G_AKTIF++;
        pthread_mutex_unlock(&G_M);
        gez_klasor(n->yol); free(n->yol); free(n);
        pthread_mutex_lock(&G_M); G_AKTIF--; pthread_cond_broadcast(&G_C); pthread_mutex_unlock(&G_M);
    }
}

static void agaci_gez(const char *hedef) {                 // klasörler paralel taranır; sıra sonra kesinleşir
    struct stat st;
    if (lstat(hedef, &st)) die(hedef);
    if (S_ISDIR(st.st_mode)) {
        ekle(strdup(hedef + KOK_LEN), &st, 1); gez_ekle(strdup(hedef));
        pthread_t t[8];
        for (int i = 0; i < 8; i++) pthread_create(&t[i], NULL, gez_is, NULL);
        for (int i = 0; i < 8; i++) pthread_join(t[i], NULL);
    } else if (S_ISREG(st.st_mode)) ekle(strdup(hedef + KOK_LEN), &st, 0);
    else ATLANAN_BAG++;
}

// Klasörler önce, derinlik sırasıyla (üst, alttan önce gelir). Dosyalar klasör klasör, her klasörde inode sırasıyla: gerçek diskte arama azalır, klasör tanıtıcısı tekrar kullanılır.
static int sira_kiyas(const void *pa, const void *pb) {
    const ent_t *a = pa, *b = pb;
    if (a->type != b->type) return a->type ? -1 : 1;
    if (a->type) return a->sira != b->sira ? (a->sira < b->sira ? -1 : 1) : strcmp(a->name, b->name);
    const char *sa = strrchr(a->name, '/'), *sb = strrchr(b->name, '/');
    size_t la = sa ? (size_t)(sa - a->name) : 0, lb = sb ? (size_t)(sb - b->name) : 0, l = la < lb ? la : lb;
    int c = memcmp(a->name, b->name, l);
    if (c) return c;
    if (la != lb) return la < lb ? -1 : 1;
    return a->ino < b->ino ? -1 : a->ino > b->ino;
}

static void dosyalari_diz(void) {
    uint64_t v = 0; NF = 0; FI = malloc((NE + 1) * sizeof *FI);
    for (size_t i = 0; i < NE; i++) {
        E[i].voff = v;
        if (!E[i].type && E[i].size) { if (E[i].size > UINT64_MAX - v) die2("boy tasti"); v += E[i].size; FI[NF++] = &E[i]; }
    }
    TOTAL = v;
    if (!CH) {                                               // gönderen seçer: parça başına yaklaşık 128 dosya, en az 256 KiB, en çok 8 MiB
        uint64_t hedef = NF ? TOTAL / NF * 128 : CHUNK; CH = MIN_CH;
        while (CH < CHUNK && CH < hedef) CH <<= 1;
    }
    NCHUNK = (TOTAL + CH - 1) / CH;
    BITS = calloc(NCHUNK / 8 + 1, 1);
}

static uint8_t *manifest_yaz(uint64_t *len) {
    size_t cap = 0; for (size_t i = 0; i < NE; i++) cap += 23 + strlen(E[i].name);
    uint8_t *m = malloc(cap + 64), *p = m;
    for (size_t i = 0; i < NE; i++) {
        uint16_t nl = (uint16_t)strlen(E[i].name);
        *p++ = E[i].type; memcpy(p, &E[i].mode, 4); p += 4; memcpy(p, &E[i].mtime, 8); p += 8; memcpy(p, &E[i].size, 8); p += 8;
        memcpy(p, &nl, 2); p += 2; memcpy(p, E[i].name, nl); p += nl;
    }
    *len = (uint64_t)(p - m);
    return m;
}

static int ad_guvenli(const char *n) {
    if (!*n || *n == '/') return 0;                          // Linux'ta ters bölü sıradan bir karakterdir
    for (const char *p = n; *p;) {
        const char *q = strchr(p, '/'); size_t l = q ? (size_t)(q - p) : strlen(p);
        if (!l || (l == 2 && !memcmp(p, "..", 2)) || (l == 1 && *p == '.')) return 0;
        if (!q) break;
        p = q + 1;
    }
    return 1;
}

static void manifest_oku(const uint8_t *m, uint64_t len) {
    const uint8_t *p = m, *son = m + len;
    while (p < son) {
        if (son - p < 23) die2("manifest kisa");
        ent_t e = {0}; uint16_t nl;
        e.type = *p++; memcpy(&e.mode, p, 4); p += 4; memcpy(&e.mtime, p, 8); p += 8; memcpy(&e.size, p, 8); p += 8; memcpy(&nl, p, 2); p += 2;
        if ((size_t)(son - p) < nl || e.type > 1) die2("manifest bozuk");
        e.name = strndup((const char *)p, nl); p += nl;
        if (strlen(e.name) != nl || !ad_guvenli(e.name)) { fprintf(stderr, "HATA guvensiz yol reddedildi: %s\n", e.name); exit(1); }
        if (NE == CAP_E) { CAP_E = CAP_E ? CAP_E * 2 : 1024; E = realloc(E, CAP_E * sizeof *E); }
        E[NE++] = e;
    }
}

static void mkdir_p(const char *yolu) {
    char t[PATH_MAX]; snprintf(t, sizeof t, "%s", yolu);
    for (char *p = t + 1; *p; p++) if (*p == '/') { *p = 0; if (mkdir(t, 0755) && errno != EEXIST) die(t); *p = '/'; }
    if (mkdir(t, 0755) && errno != EEXIST) die(t);
}

static void durum_yolu(char *p, size_t n) { yol(p, n, STATE); }

// Bit haritası anlık alınır, sonra syncfs: durum dosyasına yalnız diske ulaşmış parçalar yazılır.
static void *durum_is(void *arg) {
    (void)arg; size_t bl = NCHUNK / 8 + 1; uint8_t *s = malloc(bl); char p[PATH_MAX]; durum_yolu(p, sizeof p);
    int dfd = open(BASE, O_RDONLY), fd = open(p, O_WRONLY | O_CREAT, 0600); double bekle = 2;
    if (dfd < 0 || fd < 0) die("durum");
    while (!BITTI) {
        for (double t = now(); now() - t < bekle && !BITTI;) usleep(100000);
        if (BITTI) break;
        for (size_t i = 0; i < bl; i++) s[i] = atomic_load(&BITS[i]);
        double t = now(); syncfs(dfd);
        if (pwrite(fd, MHASH, 32, 0) != 32 || pwrite(fd, s, bl, 32) != (ssize_t)bl) die("durum yaz");
        fdatasync(fd);
        bekle = 10 * (now() - t); if (bekle < 2) bekle = 2;  // disk zamanının en çok onda biri kaydete gider
    }
    close(fd); close(dfd); free(s);
    return NULL;
}

static size_t *BOS; static size_t NBOS; static _Atomic size_t BOS_I;

static void *bos_is(void *arg) {                          // boş dosyalar parçaya girmez, ayrıca paralel oluşturulur
    (void)arg; fdc_t fc = FDC_BOS;
    for (size_t i; (i = atomic_fetch_add(&BOS_I, 1)) < NBOS;) tek_yaz(&fc, &E[BOS[i]], NULL);
    if (fc.dfd >= 0) close(fc.dfd);
    return NULL;
}

static int calis_send(int argc, char **argv) {
    (void)argc; const char *host = argv[2]; int port = atoi(argv[3]); STREAMS = atoi(argv[4]); char *hedef = realpath(argv[5], NULL);
    if (!hedef) die(argv[5]);
    if (STREAMS < 1 || STREAMS > 256) die2("akis 1-256");
    char *kes = strrchr(hedef, '/'); static char ust[PATH_MAX];
    snprintf(ust, sizeof ust, "%.*s", kes == hedef ? 1 : (int)(kes - hedef), hedef); BASE = ust; KOK_LEN = (size_t)(kes - hedef) + 1;
    double t_gez = now();
    agaci_gez(hedef);
    qsort(E, NE, sizeof *E, sira_kiyas); t_gez = now() - t_gez;
#ifdef AKTAR_TEST
    if (getenv("AKTAR_TEST_NAME")) { free(E[0].name); E[0].name = strdup(getenv("AKTAR_TEST_NAME")); }
#endif
    dosyalari_diz();
    const char *lim = getenv("AKTAR_LIMIT_MBS"); if (lim) LIMIT = atof(lim) * 1e6 / STREAMS;
    int ur = open("/dev/urandom", O_RDONLY); if (ur < 0 || read(ur, SALT, 16) != 16) die("urandom"); close(ur);
    int k = baglan(host, port);
    if (full_io(k, RNONCE, 16, 0, 0)) die("nonce");
    derive();
    uint64_t ml; uint8_t *m = manifest_yaz(&ml); EVP_CIPHER_CTX *c = ctx_yeni(1);
    hello_t he = {.magic = MAGIC, .streams = (uint32_t)STREAMS, .total = TOTAL, .mlen = ml, .chunk = CH}; memcpy(he.salt, SALT, 16);
    if (gcm(c, 1, 2, 0, &he, offsetof(hello_t, tag), m, (int)ml, he.tag)) die2("gcm");
    double t0 = now();
    if (full_io(k, &he, sizeof he, 1, 0) || full_io(k, m, ml, 1, 0)) die("hello");
    size_t bl = NCHUNK / 8 + 1; uint8_t *b = malloc(bl), tg[16]; EVP_CIPHER_CTX *d = ctx_yeni(0);
    if (full_io(k, b, bl, 0, 0) || full_io(k, tg, 16, 0, 0)) die2("alici yanit vermedi (anahtar yanlis olabilir)");
    if (gcm(d, 0, 3, 0, NULL, 0, b, (int)bl, tg)) die2("alici anahtari kanitlayamadi");
    uint64_t atla = 0;
    for (uint64_t i = 0; i < NCHUNK; i++) if (b[i / 8] >> (i % 8) & 1) { atomic_fetch_or(&BITS[i / 8], (uint8_t)(1u << (i % 8))); atla += raw_of(i); }
    conn_t ct = {host, port}; pthread_t th[256];
    for (int i = 0; i < STREAMS; i++) pthread_create(&th[i], NULL, sender, &ct);
    for (int i = 0; i < STREAMS; i++) pthread_join(th[i], NULL);
    uint8_t son[2];
    if (full_io(k, son, 2, 0, 0) || memcmp(son, "OK", 2)) die2("alici tamamlandi demedi");
    double dt = now() - t0;
    printf("{\"rol\":\"gonder\",\"bayt\":%llu,\"sn\":%.3f,\"GBs\":%.3f,\"kablo_bayt\":%llu,\"zstd_parca\":%llu,\"akis\":%d,\"dosya\":%zu,\"oge\":%zu,\"atlanan_ozel\":%llu,\"devam_atlanan\":%llu,\"gezinti_sn\":%.3f,\"parca\":%u}\n",
           (unsigned long long)TOTAL, dt, (TOTAL - atla) / 1e9 / dt, (unsigned long long)WIRE_BYTES, (unsigned long long)ZCHUNKS, STREAMS, NF, NE, (unsigned long long)ATLANAN_BAG, (unsigned long long)atla, t_gez, CH);
    return 0;
}

static int calis_recv(int argc, char **argv) {
    (void)argc; int port = atoi(argv[2]); BASE = argv[3]; mkdir_p(BASE); umask(0);        // dosya kipi oluştururken kesin verilir
    int ur = open("/dev/urandom", O_RDONLY); if (ur < 0 || read(ur, RNONCE, 16) != 16) die("urandom"); close(ur);
    int ls = socket(AF_INET, SOCK_STREAM, 0), one = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = INADDR_ANY};
    if (bind(ls, (void *)&a, sizeof a) || listen(ls, 256)) die("listen");
    int k = accept(ls, NULL, NULL); if (k < 0) die("accept"); tune(k);
    if (full_io(k, RNONCE, 16, 1, 0)) die("nonce");
    hello_t he;
    if (full_io(k, &he, sizeof he, 0, 0) || he.magic != MAGIC) die2("hello bozuk");
    if (he.mlen > MAKS_MANIFEST || he.streams < 1 || he.streams > 256 || he.chunk < MIN_CH || he.chunk > CHUNK || (he.chunk & (he.chunk - 1))) die2("hello gecersiz");
    CH = he.chunk;
    memcpy(SALT, he.salt, 16); derive();
    uint8_t *m = malloc(he.mlen + 16); EVP_CIPHER_CTX *d = ctx_yeni(0), *c = ctx_yeni(1);
    double t0 = now();
    if (he.mlen && full_io(k, m, he.mlen, 0, 0)) die("manifest");
    if (gcm(d, 0, 2, 0, &he, offsetof(hello_t, tag), m, (int)he.mlen, he.tag)) die2("anahtar yanlis veya manifest degismis");
    manifest_oku(m, he.mlen); dosyalari_diz();
    if (TOTAL != he.total) die2("toplam boy tutmadi");
    STREAMS = (int)he.streams;
    blake3_hasher bh; blake3_hasher_init(&bh); blake3_hasher_update(&bh, m, he.mlen); blake3_hasher_finalize(&bh, MHASH, 32);
    size_t bl = NCHUNK / 8 + 1; char sp[PATH_MAX]; durum_yolu(sp, sizeof sp); int devam = 0;
    int sf = open(sp, O_RDONLY);
    if (sf >= 0) {
        uint8_t h[32], *b = malloc(bl);
        if (read(sf, h, 32) == 32 && !memcmp(h, MHASH, 32) && read(sf, b, bl) == (ssize_t)bl) { for (size_t i = 0; i < bl; i++) atomic_store(&BITS[i], b[i]); devam = 1; }
        close(sf); free(b);
    }
    double t_dizin = now(); BOS = malloc((NE + 1) * sizeof *BOS);
    for (size_t i = 0; i < NE; i++) {                        // manifestte klasörler önce: dosyalar açılırken üstleri hazır
        if (!E[i].type && E[i].size && TEK(&E[i])) continue;
        if (!E[i].type && !E[i].size) { BOS[NBOS++] = i; continue; }
        char p[PATH_MAX]; yol(p, sizeof p, E[i].name);
        if (E[i].type) {
            if (mkdir(p, 0755) && errno != EEXIST) { if (errno == ENOENT) mkdir_p(p); else die(p); }
            continue;
        }
        int fd = open(p, O_WRONLY | O_CREAT | O_NOFOLLOW | (devam ? 0 : O_TRUNC), 0600);     // birden çok parçaya yayılan dosya
        if (fd < 0 || ftruncate(fd, (off_t)E[i].size)) die(p);
        close(fd);
    }
    t_dizin = now() - t_dizin;
    uint8_t *b = malloc(bl + 16), tg[16];
    for (size_t i = 0; i < bl; i++) b[i] = atomic_load(&BITS[i]);
    uint64_t onceki = 0; for (uint64_t i = 0; i < NCHUNK; i++) if (b[i / 8] >> (i % 8) & 1) onceki += raw_of(i);
    if (gcm(c, 1, 3, 0, NULL, 0, b, (int)bl, tg)) die2("gcm");
    if (full_io(k, b, bl, 1, 0) || full_io(k, tg, 16, 1, 0)) die("bitharitasi");
    pthread_t dt_, th[256], bt[4]; pthread_create(&dt_, NULL, durum_is, NULL);
    double t_veri = now();
    for (int i = 0; i < 4; i++) pthread_create(&bt[i], NULL, bos_is, NULL);
    for (int i = 0; i < STREAMS; i++) {
        int s = accept(ls, NULL, NULL); if (s < 0) die("accept"); tune(s);
        if (full_io(s, RNONCE, 16, 1, 0)) die("nonce");
        pthread_create(&th[i], NULL, receiver, (void *)(intptr_t)s);
    }
    for (int i = 0; i < STREAMS; i++) pthread_join(th[i], NULL);
    for (int i = 0; i < 4; i++) pthread_join(bt[i], NULL);
    t_veri = now() - t_veri;
    BITTI = 1; pthread_join(dt_, NULL);
    for (uint64_t i = 0; i < NCHUNK; i++) if (!(atomic_load(&BITS[i / 8]) >> (i % 8) & 1)) die2("eksik parca");
    double t_meta = now();
    for (size_t i = NE; i-- > 0;) {                          // tek parçalık ve boş dosyalar yazılırken tamamlandı
        if (!E[i].type && (!E[i].size || TEK(&E[i]))) continue;
        char p[PATH_MAX]; yol(p, sizeof p, E[i].name);
        struct utimbuf u = {E[i].mtime, E[i].mtime}; chmod(p, E[i].mode & 0777); utime(p, &u);     // setuid/setgid taşınmaz
    }
    t_meta = now() - t_meta;
    double t_sync = now(); int dfd = open(BASE, O_RDONLY); if (dfd >= 0) { syncfs(dfd); close(dfd); } t_sync = now() - t_sync;
    unlink(sp);
    if (full_io(k, "OK", 2, 1, 0)) die("son");
    double dt = now() - t0;
    printf("{\"rol\":\"al\",\"bayt\":%llu,\"sn\":%.3f,\"GBs\":%.3f,\"devam\":%d,\"onceki_bayt\":%llu,\"dizin_sn\":%.3f,\"veri_sn\":%.3f,\"meta_sn\":%.3f,\"sync_sn\":%.3f}\n",
           (unsigned long long)DONE_BYTES, dt, DONE_BYTES / 1e9 / dt, devam, (unsigned long long)onceki, t_dizin, t_veri, t_meta, t_sync);
    return 0;
}

int main(int argc, char **argv) {
    parse_key();
    if (argc >= 6 && !strcmp(argv[1], "send")) return calis_send(argc, argv);
    if (argc >= 4 && !strcmp(argv[1], "recv")) return calis_recv(argc, argv);
    fprintf(stderr, "kullanim: AKTAR_KEY=<64hex> aktar2 send <host> <port> <akis> <yol> | aktar2 recv <port> <cikti>\n");
    return 2;
}
