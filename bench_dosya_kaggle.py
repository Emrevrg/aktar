# Aktar dosya/saniye ölçümü (Kaggle CPU, loopback): eski sürüm, yeni sürüm, cp -a, tar|tar, şifresiz tar|nc aynı koşuda. Süre, gönderen sürecinin başından sonuna duvar saati.
# Gönderen ve alıcı aynı makineyi paylaşır; iki makine sonucu değildir. Sonra bench2 tüm güvenlik ve devam testlerini yeni sürümde yeniden koşar.
import errno, hashlib, json, os, shutil, statistics, subprocess, time
W = "/kaggle/working"; S = "/dev/shm/ak"; shutil.rmtree(S, ignore_errors=True); os.makedirs(S)
sh = lambda c, **k: subprocess.run(c, shell=True, capture_output=True, text=True, **k)
D = {"cpu": os.cpu_count(), "uname": os.uname().release}
kayit = lambda: json.dump(D, open(f"{W}/aktar_dosya.json", "w"), indent=1, ensure_ascii=False)
sh("apt-get -qq update >/dev/null 2>&1; apt-get -qq install -y libssl-dev libzstd-dev netcat-openbsd >/dev/null 2>&1")
sh(f"cd {W} && git clone -q --depth 1 https://github.com/BLAKE3-team/BLAKE3 b3 && mkdir -p blake3 && cp b3/c/*.c b3/c/*.h blake3/")
obj = []
for f, fl in (("blake3", ""), ("blake3_dispatch", ""), ("blake3_portable", ""), ("blake3_sse2", "-msse2"), ("blake3_sse41", "-msse4.1"), ("blake3_avx2", "-mavx2"), ("blake3_avx512", "-mavx512f -mavx512vl")):
    sh(f"cd {W} && gcc -O3 -c {fl} blake3/{f}.c -o blake3/{f}.o"); obj.append(f"blake3/{f}.o")
for ad, kay in (("yeni", "aktar2.c"), ("taban", "aktar2_taban.c")):
    r = sh(f"cd {W} && gcc -O3 -march=native -pthread -Wall {kay} {' '.join(obj)} -lssl -lcrypto -lzstd -o a_{ad}")
    D[f"derleme_{ad}"] = "ok" if r.returncode == 0 else r.stderr[-1500:]; D[f"uyari_{ad}"] = r.stderr[-800:]
print(D, flush=True); kayit()
try:                                                      # io_uring açık mı: sonraki adımın kararı
    import ctypes
    r = ctypes.CDLL(None, use_errno=True).syscall(425, 4, ctypes.create_string_buffer(120)); e = ctypes.get_errno(); D["io_uring"] = "acik" if r >= 0 else errno.errorcode.get(e, str(e))
except Exception as ex:  # noqa: BLE001
    D["io_uring"] = repr(ex)


def agac_gercek(A, kok_list, sinir=200000, bayt=3 << 30):
    say = bay = 0; os.makedirs(A)
    for kok in kok_list:
        for d, _, fs in os.walk(kok):
            for f in fs:
                p = os.path.join(d, f)
                try:
                    if os.path.islink(p) or not os.path.isfile(p):
                        continue
                    z = os.path.getsize(p)
                    if z > 1 << 20 or say >= sinir or bay + z > bayt:
                        continue
                    q = os.path.join(A, os.path.relpath(d, "/"), f); os.makedirs(os.path.dirname(q), exist_ok=True); shutil.copy2(p, q); say += 1; bay += z
                except OSError:
                    pass
    return say, bay


def agac_sentetik(A, n, boy, her=1000):
    b = os.urandom(boy)
    for i in range(n):
        if i % her == 0:
            d = f"{A}/d{i // her:05d}"; os.makedirs(d)
        with open(f"{d}/f{i:07d}", "wb") as f:
            f.write(b)
    return n, n * boy


def ozet(kok):
    h = hashlib.sha256(); n = 0
    for d, ds, fs in os.walk(kok):
        ds.sort(); st = os.stat(d); h.update(f"D{os.path.relpath(d, kok)}:{st.st_mode}:{int(st.st_mtime)}\n".encode())
        for f in sorted(fs):
            p = os.path.join(d, f); st = os.lstat(p)
            if not os.path.isfile(p) or os.path.islink(p):
                continue
            with open(p, "rb") as fh:
                c = hashlib.sha256(fh.read()).digest()
            h.update(f"F{os.path.relpath(p, kok)}:{st.st_mode & 0o777}:{int(st.st_mtime)}:".encode() + c); n += 1
    return h.hexdigest(), n


KEY = os.urandom(32).hex(); pt = [8000]


def aktar(bin_, yol, akis, cikti):
    pt[0] += 1; shutil.rmtree(cikti, ignore_errors=True); env = dict(os.environ, AKTAR_KEY=KEY, AKTAR_ZSTD="0")
    rx = subprocess.Popen(f"{W}/{bin_} recv {pt[0]} {cikti}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env); time.sleep(0.3)
    t = time.time(); tx = subprocess.run(f"{W}/{bin_} send 127.0.0.1 {pt[0]} {akis} {yol}", shell=True, capture_output=True, text=True, env=env, timeout=1800); a, b = rx.communicate(timeout=300); sn = time.time() - t
    if tx.returncode or rx.returncode:
        return {"hata": (tx.stderr + b)[-300:]}
    return {"sn": sn, "gon": json.loads(tx.stdout.strip().splitlines()[-1]), "al": json.loads(a.strip().splitlines()[-1])}


def kiyas(ad, A, cikti, n):
    R = {"dosya": n}; ref = ozet(A); shutil.rmtree(cikti, ignore_errors=True)
    for k, cmd in (("cp_a", f"cp -a {A} {cikti}"), ("tar_tar", f"mkdir -p {cikti} && tar cf - -C {os.path.dirname(A)} {os.path.basename(A)} | tar xf - -C {cikti}")):
        s = []
        for _ in range(3):
            shutil.rmtree(cikti, ignore_errors=True); t = time.time(); sh(cmd); s.append(time.time() - t)
        R[k] = {"sn": round(statistics.median(s), 3), "dosya_sn": round(n / statistics.median(s))}
    shutil.rmtree(cikti, ignore_errors=True)
    s = []
    for _ in range(3):
        pt[0] += 1; shutil.rmtree(cikti, ignore_errors=True); os.makedirs(cikti); rx = subprocess.Popen(f"nc -l -p {pt[0]} | tar xf - -C {cikti}", shell=True); time.sleep(0.4)
        t = time.time(); sh(f"tar cf - -C {os.path.dirname(A)} {os.path.basename(A)} | nc -q 0 127.0.0.1 {pt[0]}"); rx.wait(timeout=900); s.append(time.time() - t)
    R["tar_nc_sifresiz"] = {"sn": round(statistics.median(s), 3), "dosya_sn": round(n / statistics.median(s))}
    print(ad, R, flush=True)
    for bin_, akislar in (("a_taban", (4,)), ("a_yeni", (2, 4, 8, 16))):
        for ak in akislar:
            o = [aktar(bin_, A, ak, cikti) for _ in range(3)]; ok = [x for x in o if "sn" in x]
            if not ok:
                R[f"{bin_}|{ak}"] = o[0]; continue
            m = statistics.median(x["sn"] for x in ok); e = {"sn": round(m, 3), "dosya_sn": round(n / m), "gon": ok[-1]["gon"], "al": ok[-1]["al"]}
            y = os.path.join(cikti, os.path.basename(A)); e["ayni"] = ozet(y)[0] == ref[0] if os.path.isdir(y) else False
            R[f"{bin_}|{ak}"] = e; print(ad, bin_, ak, {k: e[k] for k in ("sn", "dosya_sn", "ayni")}, flush=True); D[ad] = R; kayit()
    shutil.rmtree(cikti, ignore_errors=True); return R


A1 = f"{S}/gercek"; n1, b1 = agac_gercek(A1, ("/opt/conda", "/usr/lib", "/usr/share", "/usr/include")); D["gercek_agac"] = {"dosya": n1, "bayt": b1}; print(D["gercek_agac"], flush=True)
D["gercek"] = kiyas("gercek", A1, f"{S}/c", n1); shutil.rmtree(A1, ignore_errors=True)
A2 = f"{S}/kucuk"; n2, b2 = agac_sentetik(A2, 300000, 1024); D["kucuk_1KB"] = kiyas("kucuk_1KB", A2, f"{S}/c", n2); shutil.rmtree(A2, ignore_errors=True)
A3 = f"{S}/bos"; n3, b3 = agac_sentetik(A3, 200000, 0); D["bos_dosya"] = kiyas("bos_dosya", A3, f"{S}/c", n3); shutil.rmtree(A3, ignore_errors=True)
kayit(); print("DOSYA_OLCUM_BITTI", flush=True)
shutil.rmtree(S, ignore_errors=True)
