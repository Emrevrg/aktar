# Aktar

Encrypted folder and file transfer over a direct cable, built to move many small files fast.

Small files are packed into chunks and sent over parallel TCP streams with AES-256-GCM. The receiver authenticates each chunk before writing it. Interrupted transfers resume where they stopped.

## Measured: files per second

All tests: sender and receiver on the same machine over loopback, files in `/dev/shm`, median of 3 runs, wall clock of the sending process. Aktar runs with encryption on. `tar | tar` uses no network or encryption; `tar | nc` is unencrypted.

**26-core server, Linux 6.8, best stream count for each.** Another CPU job was running on the server at the same time.

| Tree | Aktar | Aktar first version | `tar \| tar` | `tar \| nc` | `cp -a` |
|---|---|---|---|---|---|
| Real tree, 92,453 files, 1.44 GB | **112,888** | 44,978 | 63,305 | 56,009 | 52,750 |
| 300,000 files of 1 KB | **281,329** | 91,980 | 174,033 | 166,498 | 102,050 |
| 200,000 empty files | **286,385** | 106,768 | 287,702 | 282,874 | 130,544 |

Empty files are a tie with `tar | tar`. A 100 GB file reached 2.35 GB/s with 4 streams; more streams were slower on this setup. At that rate 1 TB would take about 7 minutes, but a full 1 TB was not run.

**Kaggle CPU, 4 vCPU, 4 streams:**

| Tree | Aktar, 4 streams | Aktar first version | `tar \| tar` | `tar \| nc` | `cp -a` |
|---|---|---|---|---|---|
| Real tree, 84,239 files, 1.33 GB | **39,873** | 15,508 | 25,022 | 17,512 | 19,078 |
| 300,000 files of 1 KB | **92,580** | 27,451 | 47,685 | 36,454 | 26,916 |
| 200,000 empty files | **127,132** | 33,561 | 67,317 | 59,051 | 30,111 |

Content, file mode and mtime matched after every Aktar run.

**Limits of this result.** One machine and a RAM disk. Two real machines and real disks have not been measured, and those numbers will differ. Your own run is the one that counts.

## Security

The session key comes from a shared key and fresh nonces from both sides. Chunk headers are authenticated, so chunks cannot be swapped, and recorded sessions cannot be replayed. Paths are checked on the receiver.

`bench2_kaggle.py` attacks a real transfer. All 10 attacks were rejected: flipped bytes in the hello, manifest, chunk headers and chunk data, a second-stream header, session replay, a wrong key, and three malicious paths.

These are my own tests. The code has not had an independent security audit, so don't rely on it for high-risk data yet.

## Build

Linux, with OpenSSL, zstd and [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) C sources in `blake3/`, compiled to objects:

```bash
gcc -O3 -march=native -pthread aktar2.c blake3/*.o -lssl -lcrypto -lzstd -o aktar2
```

## Use

```bash
export AKTAR_KEY=$(openssl rand -hex 32)      # same key on both machines
./aktar2 recv 7000 ./output                    # receiver
./aktar2 send 192.168.1.20 7000 4 ./folder     # sender: host, port, streams, path
```

Symbolic links and special files are skipped and counted. Run the same command again to resume.

## Reproduce

`bench_dosya_kaggle.py` runs the table above and `bench2_kaggle.py` runs the security and resume tests. Both are written as Kaggle CPU scripts that use `/kaggle/working`. `aktar2_taban.c` is the first version used for comparison, and `aktar_core.c` is the earlier core.

MIT License. Norovox Labs.
