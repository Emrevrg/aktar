# Aktar v2 ölçümü (Kaggle CPU, loopback, veriler /dev/shm'de): hız, bayt bayt doğruluk, güvenlik saldırıları, kaldığı yerden devam, küçük dosya ağacı.
# Kıyas: Aktar v1 (aynı makine), cp -a, tar|nc (şifresiz). Gönderen ve alıcı aynı 4 vCPU'yu paylaşır; iki makine sonucu değildir.
import hashlib, json, os, shutil, signal, socket, subprocess, threading, time
W = "/kaggle/working"; S = "/dev/shm/ak"; shutil.rmtree(S, ignore_errors=True); os.makedirs(S)
sh = lambda c, **k: subprocess.run(c, shell=True, capture_output=True, text=True, **k)
R = {"cpu": os.cpu_count(), "bellek_GB": round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30, 1)}
kaydet = lambda: json.dump(R, open(f"{W}/aktar2.json", "w"), indent=1, ensure_ascii=False)
sh("apt-get -qq update >/dev/null 2>&1; apt-get -qq install -y libssl-dev libzstd-dev netcat-openbsd >/dev/null 2>&1")
sh(f"cd {W} && git clone -q --depth 1 https://github.com/BLAKE3-team/BLAKE3 b3 && mkdir -p blake3 && cp b3/c/*.c b3/c/*.h blake3/")
objs = []
for f, fl in (("blake3", ""), ("blake3_dispatch", ""), ("blake3_portable", ""), ("blake3_sse2", "-msse2"), ("blake3_sse41", "-msse4.1"),
              ("blake3_avx2", "-mavx2"), ("blake3_avx512", "-mavx512f -mavx512vl")):
    sh(f"cd {W} && gcc -O3 -c {fl} blake3/{f}.c -o blake3/{f}.o"); objs.append(f"blake3/{f}.o")
o = " ".join(objs)
r = sh(f"cd {W} && gcc -O3 -march=native -pthread -Wall -DAKTAR_TEST aktar2.c {o} -lssl -lcrypto -lzstd -o aktar2")
R["derleme_v2"] = "ok" if r.returncode == 0 else "HATA"; R["derleme_uyari"] = r.stderr[-2500:]
r1 = sh(f"cd {W} && gcc -O3 -march=native -pthread aktar_core.c {o} -lssl -lcrypto -lzstd -o aktar_core")
R["derleme_v1"] = "ok" if r1.returncode == 0 else r1.stderr[-500:]
print(R, flush=True); kaydet()
if R["derleme_v2"] != "ok":
    print("SONUC_AKTAR2", json.dumps(R)[-3000:]); os._exit(0)
R["openssl_tek_cekirdek"] = sh("openssl speed -seconds 2 -evp aes-256-gcm -bytes 8388608 2>&1 | tail -2").stdout[-300:]

GB = 4; SIZE = GB << 30
sh(f"head -c {GB}G /dev/urandom > {S}/rastgele.bin")
sh(f"(find /usr/lib/python3* /opt/conda/lib/python3* /usr/include -type f \\( -name '*.py' -o -name '*.h' \\) 2>/dev/null | head -6000 | xargs cat) > {S}/k1.bin")
src = open(f"{S}/k1.bin", "rb").read()
with open(f"{S}/karma.bin", "wb") as f:
    left = SIZE
    while left > 0:
        k = min(left, len(src)); f.write(src[:k]); left -= k
os.remove(f"{S}/k1.bin")
os.makedirs(f"{S}/g_r"); os.makedirs(f"{S}/g_k"); os.rename(f"{S}/rastgele.bin", f"{S}/g_r/rastgele.bin"); os.rename(f"{S}/karma.bin", f"{S}/g_k/karma.bin")


def agac_ozet(kok):
    h = hashlib.sha256(); n = b = 0
    for d, ds, fs in sorted(os.walk(kok)):
        ds.sort()
        rel = os.path.relpath(d, kok); h.update(f"D{rel}\n".encode())
        for f in sorted(fs):
            p = os.path.join(d, f)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            q = hashlib.sha256()
            with open(p, "rb") as fh:
                for c in iter(lambda: fh.read(1 << 20), b""):
                    q.update(c)
            h.update(f"F{rel}/{f}:".encode() + q.digest()); n += 1; b += os.path.getsize(p)
    return h.hexdigest(), n, b


KEY = os.urandom(32).hex(); port = [7000]


def yeni_port():
    port[0] += 1
    return port[0]


def rx_baslat(p, out, key=None, env=None):
    return subprocess.Popen(f"{W}/aktar2 recv {p} {out}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid,
                            env=dict(os.environ, AKTAR_KEY=key or KEY, **(env or {})))


def v2(yol, akis, z=-1, limit=None, out=None, temizle=True, env=None):
    p = yeni_port(); out = out or f"{S}/cikti"
    if temizle:
        shutil.rmtree(out, ignore_errors=True)
    rx = rx_baslat(p, out); time.sleep(0.3)
    e = dict(os.environ, AKTAR_KEY=KEY, AKTAR_ZSTD=str(z), **(env or {}))
    if limit:
        e["AKTAR_LIMIT_MBS"] = str(limit)
    tx = subprocess.run(f"{W}/aktar2 send 127.0.0.1 {p} {akis} {yol}", shell=True, capture_output=True, text=True, env=e, timeout=3000)
    a, b = rx.communicate(timeout=120)
    r = {"gonder": tx.stdout.strip()[-400:], "al": a.strip()[-200:], "tx_kod": tx.returncode, "rx_kod": rx.returncode, "tx_hata": tx.stderr[-200:], "rx_hata": b[-200:]}
    try:
        g = json.loads(tx.stdout.strip().splitlines()[-1]); r.update(GBs=g["GBs"], sn=g["sn"], kablo=g["kablo_bayt"], zstd_parca=g["zstd_parca"])
    except Exception:  # noqa: BLE001
        pass
    return r


# 1) hız: v2, v1 ve doğrulama
H = {n: agac_ozet(f"{S}/{n}")[0] for n in ("g_r", "g_k")}
R["hiz"] = {}
for ad, n in (("rastgele", "g_r"), ("karma", "g_k")):
    for akis in (1, 2, 4):
        for z in ((0,) if ad == "rastgele" else (0, -1)):
            k = f"{ad}|akis{akis}|z{z}"; r = v2(f"{S}/{n}", akis, z)
            r["bayt_ayni"] = r["rx_kod"] == 0 and agac_ozet(f"{S}/cikti/{n}")[0] == agac_ozet(f"{S}/{n}")[0]
            R["hiz"][k] = {x: r.get(x) for x in ("GBs", "sn", "kablo", "zstd_parca", "bayt_ayni", "rx_hata")}; print(k, R["hiz"][k], flush=True); kaydet()
R["v1"] = {}
for ad, n, fn in (("rastgele", "g_r", "rastgele.bin"), ("karma", "g_k", "karma.bin")):
    p = yeni_port(); out = f"{S}/v1.bin"
    rx = subprocess.Popen(f"{W}/aktar_core recv {p} 4 {KEY} {out}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True); time.sleep(0.3)
    tx = subprocess.run(f"{W}/aktar_core send 127.0.0.1 {p} 4 {KEY} {S}/{n}/{fn}", shell=True, capture_output=True, text=True, env=dict(os.environ, AKTAR_ZSTD="0"), timeout=1800)
    a_, b_ = rx.communicate(timeout=120)
    try:
        R["v1"][ad] = json.loads(tx.stdout.strip().splitlines()[-1])["GBs"]
    except Exception as e:  # noqa: BLE001
        R["v1"][ad] = {"hata": repr(e), "tx": tx.stdout[-200:], "tx_err": tx.stderr[-200:], "rx": a_[-200:], "rx_err": b_[-200:]}
    if os.path.exists(out):
        os.remove(out)
print("v1", R["v1"], flush=True); kaydet()

# 2) bağlantı benzetimi: uyarlanır zstd yavaş bağlantıda açılıyor, hızlıda kapanıyor mu
R["baglanti"] = {}
for lim in (117, 1170):      # 1GbE ve 10GbE yükü
    for z in (0, -1):
        r = v2(f"{S}/g_k", 4, z, limit=lim); k = f"{lim}MBs|z{z}"
        R["baglanti"][k] = {x: r.get(x) for x in ("GBs", "sn", "kablo", "zstd_parca", "rx_hata")}; print(k, R["baglanti"][k], flush=True); kaydet()
r = v2(f"{S}/g_r", 4, -1, limit=117); R["baglanti"]["117MBs|rastgele|z-1"] = {x: r.get(x) for x in ("GBs", "sn", "kablo", "zstd_parca")}; kaydet()

# 3) küçük dosya ağacı (gerçek klasörler)
A = f"{S}/agac"; say = bay = 0; os.makedirs(A)
for kok in ("/opt/conda", "/usr/lib", "/usr/share", "/usr/include"):
    for d, ds, fs in os.walk(kok):
        for f in fs:
            p = os.path.join(d, f)
            try:
                if os.path.islink(p) or not os.path.isfile(p):
                    continue
                z = os.path.getsize(p)
                if z > 1 << 20 or say >= 200000 or bay + z > 3 << 30:
                    continue
                q = os.path.join(A, os.path.relpath(d, "/"), f); os.makedirs(os.path.dirname(q), exist_ok=True); shutil.copy2(p, q); say += 1; bay += z
            except OSError:
                pass
R["agac"] = {"dosya": say, "bayt": bay}; HA = agac_ozet(A)[0]; print(R["agac"], flush=True)
r = v2(A, 4, 0); R["agac"]["aktar_z0"] = {x: r.get(x) for x in ("GBs", "sn", "rx_hata")}; R["agac"]["aktar_z0"]["bayt_ayni"] = agac_ozet(f"{S}/cikti/agac")[0] == HA
r = v2(A, 4, -1); R["agac"]["aktar_zauto"] = {x: r.get(x) for x in ("GBs", "sn", "kablo")}; R["agac"]["aktar_zauto"]["bayt_ayni"] = agac_ozet(f"{S}/cikti/agac")[0] == HA
shutil.rmtree(f"{S}/cikti", ignore_errors=True); t = time.time(); sh(f"cp -a {A} {S}/cp_c"); R["agac"]["cp_sn"] = round(time.time() - t, 2); shutil.rmtree(f"{S}/cp_c", ignore_errors=True)
p = yeni_port(); os.makedirs(f"{S}/nc_c"); rx = subprocess.Popen(f"nc -l -p {p} | tar xf - -C {S}/nc_c", shell=True); time.sleep(0.5); t = time.time()
sh(f"tar cf - -C {S} agac | nc -q 0 127.0.0.1 {p}"); rx.wait(timeout=1800); R["agac"]["tar_nc_sifresiz_sn"] = round(time.time() - t, 2); shutil.rmtree(f"{S}/nc_c", ignore_errors=True)
print(R["agac"], flush=True); kaydet()

# 4) sınır durumları
B = f"{S}/sinir"; os.makedirs(f"{B}/bos_klasor"); os.makedirs(f"{B}/iç içe/ğüş")
open(f"{B}/bos.bin", "wb").close()
open(f"{B}/tam_parca.bin", "wb").write(os.urandom(8 << 20)); open(f"{B}/parca_arti1.bin", "wb").write(os.urandom((8 << 20) + 1))
open(f"{B}/iç içe/ğüş/türkçe ad.txt", "wb").write(b"merhaba\n"); os.symlink("bos.bin", f"{B}/bag")
r = v2(B, 3, -1); o1 = agac_ozet(B)[0]
R["sinir"] = {"bayt_ayni": r["rx_kod"] == 0 and o1 == agac_ozet(f"{S}/cikti/sinir")[0], "bos_klasor": os.path.isdir(f"{S}/cikti/sinir/bos_klasor"), "gonder": r["gonder"][-200:], "rx_hata": r["rx_hata"]}
print(R["sinir"], flush=True); kaydet()
os.makedirs(f"{S}/bosk"); r = v2(f"{S}/bosk", 2, -1); R["sinir"]["bos_agac_kod"] = r["rx_kod"]


# 5) güvenlik: ortadaki adam gerçek bir aktarımın baytını değiştirir; kaydedilip yeniden oynatılan oturum; yanlış anahtar; kötü yol
class Vekil:
    """Gönderen→alıcı akışını iletir; bağlantı ve bayt konumuna göre bir bayt çevirir, isterse akışı kaydeder."""

    def __init__(self, hedef, cevir=None, kayit=None):
        self.ls = socket.socket(); self.ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); self.ls.bind(("127.0.0.1", 0)); self.ls.listen(32)
        self.port = self.ls.getsockname()[1]; self.hedef = hedef; self.cevir = cevir; self.kayit = kayit; self.n = 0
        threading.Thread(target=self.dongu, daemon=True).start()

    def dongu(self):
        while True:
            c, _ = self.ls.accept(); i = self.n; self.n += 1
            s = socket.create_connection(("127.0.0.1", self.hedef))
            threading.Thread(target=self.ak, args=(c, s, i, True), daemon=True).start()
            threading.Thread(target=self.ak, args=(s, c, i, False), daemon=True).start()

    def ak(self, a, b, i, ileri):
        toplam = 0
        try:
            while True:
                d = a.recv(1 << 20)
                if not d:
                    break
                if ileri:
                    if self.kayit is not None and i == 0:
                        self.kayit.append(d)
                    if self.cevir and self.cevir[0] == i and toplam <= self.cevir[1] < toplam + len(d):
                        d = bytearray(d); d[self.cevir[1] - toplam] ^= 1; d = bytes(d)
                    toplam += len(d)
                b.sendall(d)
        except OSError:
            pass
        for x in (a, b):
            try:
                x.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def saldiri(cevir):
    p = yeni_port(); out = f"{S}/s_c"; shutil.rmtree(out, ignore_errors=True); rx = rx_baslat(p, out); time.sleep(0.2); v = Vekil(p, cevir)
    tx = subprocess.run(f"{W}/aktar2 send 127.0.0.1 {v.port} 2 {S}/sinir", shell=True, capture_output=True, text=True, env=dict(os.environ, AKTAR_KEY=KEY), timeout=120)
    try:
        rx.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        os.killpg(rx.pid, signal.SIGKILL); rx.wait()
    return {"reddedildi": rx.returncode != 0 and tx.returncode != 0, "rx_kod": rx.returncode, "tx_kod": tx.returncode, "tx_hata": tx.stderr[-120:]}


R["guvenlik"] = {"hello_cevir": saldiri((0, 3)), "manifest_cevir": saldiri((0, 60)),
                 "parca_basligi_cevir": saldiri((1, 8)), "parca_verisi_cevir": saldiri((1, 200)), "ikinci_akis_basligi_cevir": saldiri((2, 9))}
print(R["guvenlik"], flush=True); kaydet()

kay = []; p = yeni_port(); rx = rx_baslat(p, f"{S}/s_c2"); time.sleep(0.2); v = Vekil(p, None, kay)
subprocess.run(f"{W}/aktar2 send 127.0.0.1 {v.port} 2 {S}/sinir", shell=True, capture_output=True, env=dict(os.environ, AKTAR_KEY=KEY), timeout=120); rx.communicate(timeout=20)
p = yeni_port(); rx = rx_baslat(p, f"{S}/s_c3"); time.sleep(0.2)
s = socket.create_connection(("127.0.0.1", p)); s.recv(16); s.sendall(b"".join(kay))
try:
    a, b = rx.communicate(timeout=15)
except subprocess.TimeoutExpired:
    os.killpg(rx.pid, signal.SIGKILL); a, b = rx.communicate()
R["guvenlik"]["kayitli_oturumu_yeniden_oynatma"] = {"reddedildi": rx.returncode != 0, "hata": b[-100:]}
s.close()

p = yeni_port(); rx = rx_baslat(p, f"{S}/s_c4", key=os.urandom(32).hex()); time.sleep(0.2)
tx = subprocess.run(f"{W}/aktar2 send 127.0.0.1 {p} 2 {S}/sinir", shell=True, capture_output=True, text=True, env=dict(os.environ, AKTAR_KEY=KEY), timeout=60); rx.communicate(timeout=20)
R["guvenlik"]["yanlis_anahtar"] = {"reddedildi": rx.returncode != 0 and tx.returncode != 0, "dosya_yazilmadi": not os.path.exists(f"{S}/s_c4/sinir")}
for ad in ("../../kacis", "/etc/kacis", "a/../../kacis"):
    p = yeni_port(); out = f"{S}/s_c5"; shutil.rmtree(out, ignore_errors=True); rx = rx_baslat(p, out); time.sleep(0.2)
    subprocess.run(f"{W}/aktar2 send 127.0.0.1 {p} 2 {S}/sinir", shell=True, capture_output=True, env=dict(os.environ, AKTAR_KEY=KEY, AKTAR_TEST_NAME=ad), timeout=60); _, b = rx.communicate(timeout=20)
    R["guvenlik"][f"kotu_yol {ad}"] = {"reddedildi": rx.returncode != 0, "kacmadi": not os.path.exists(f"{S}/kacis") and not os.path.exists("/etc/kacis"), "hata": b[-80:]}
print(R["guvenlik"], flush=True); kaydet()

# 6) kaldığı yerden devam: gönderen ve alıcı aktarımın ortasında öldürülür, sonra aynı komut
out = f"{S}/dv"; shutil.rmtree(out, ignore_errors=True); p = yeni_port(); rx = rx_baslat(p, out); time.sleep(0.2)
e = dict(os.environ, AKTAR_KEY=KEY, AKTAR_ZSTD="0", AKTAR_LIMIT_MBS="800")
tx = subprocess.Popen(f"exec {W}/aktar2 send 127.0.0.1 {p} 4 {S}/g_r", shell=True, env=e, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(3.0); tx.kill(); tx.wait()
try:
    rx.communicate(timeout=10)
except subprocess.TimeoutExpired:
    os.killpg(rx.pid, signal.SIGKILL); rx.communicate()
r = v2(f"{S}/g_r", 4, 0, out=out, temizle=False)
R["devam"] = {"gonder": r["gonder"][-300:], "al": r["al"], "rx_kod": r["rx_kod"], "bayt_ayni": r["rx_kod"] == 0 and agac_ozet(f"{out}/g_r")[0] == H["g_r"], "durum_silindi": not os.path.exists(f"{out}/.aktar-state")}
print(R["devam"], flush=True); kaydet()
shutil.rmtree(S, ignore_errors=True)
print("SONUC_AKTAR2", json.dumps(R, ensure_ascii=False)[-6000:]); os._exit(0)
