# Aktar büyük veri ölçümü, H100 sunucusu, loopback, /dev/shm: 1 TB için 10 dakika eşiği 1,67 GB/s. Gönderen ve alıcı aynı makinede.
import hashlib, json, os, shutil, statistics, subprocess, time
W = "/mnt/norovox/aktar_olc"; S = "/dev/shm/akb"; shutil.rmtree(S, ignore_errors=True); os.makedirs(f"{S}/g")
GB = 100; blok = os.urandom(1 << 30)
with open(f"{S}/g/veri.bin", "wb") as f:
    for i in range(GB):                                  # şifreleme her parçada farklı çıktı üretir; sıkıştırma kapalı
        f.write(i.to_bytes(8, "little")); f.write(blok[8:])
KEY = os.urandom(32).hex(); R = {"GB": GB, "cpu": os.cpu_count()}; p = 9000


def ozet(y):
    h = hashlib.blake2b()
    with open(y, "rb") as f:
        for c in iter(lambda: f.read(1 << 24), b""):
            h.update(c)
    return h.hexdigest()


ref = ozet(f"{S}/g/veri.bin")
for ak in (4, 8, 16, 24):
    s = []
    for _ in range(3):
        p += 1; shutil.rmtree(f"{S}/c", ignore_errors=True); e = dict(os.environ, AKTAR_KEY=KEY, AKTAR_ZSTD="0")
        rx = subprocess.Popen(f"{W}/a_yeni recv {p} {S}/c", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=e); time.sleep(0.3)
        t = time.time(); tx = subprocess.run(f"{W}/a_yeni send 127.0.0.1 {p} {ak} {S}/g", shell=True, capture_output=True, text=True, env=e); rx.wait(); s.append(time.time() - t)
    ok = tx.returncode == 0 and ozet(f"{S}/c/g/veri.bin") == ref
    m = statistics.median(s); R[f"akis{ak}"] = {"sn": round(m, 2), "GBs": round(GB * 2**30 / 1e9 / m, 3), "ayni": ok, "tx_hata": tx.stderr[-120:]}
    print(ak, R[f"akis{ak}"], flush=True); json.dump(R, open(f"{W}/aktar_buyuk.json", "w"), indent=1)
shutil.rmtree(S, ignore_errors=True); print("BUYUK_BITTI", flush=True)
