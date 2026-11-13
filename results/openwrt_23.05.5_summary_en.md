# Evaluation: 16 OpenWrt 23.05.5 Images (`cbomscan` v0.7 `scan-image`)

> **Note:** An earlier version (v0.5) showed fewer findings; detection was expanded in v0.7 (including `DT_NEEDED` dependencies, `.ko` kernel modules, excluding `crc32c_generic.ko`/`crypto_null.ko`, flagging `libubox` MD5, and separating *contains* vs. *uses*). Total ELF file counts remain unchanged.

Scan of 16 public release images (OpenWrt 23.05.5, obtained from `downloads.openwrt.org`) across different architectures and target platforms using `cbomscan.py scan-image` (v0.7).
This is a feasibility probe on 16 OpenWrt images and makes no statement about vendor firmware. The *Quantum-vulnerable* column is a sum of findings across files, not the number of distinct vulnerabilities.

## Results per device

The per-algorithm columns count in **how many ELF files** of the respective image the algorithm was found (combining *contains* and *uses*). The *Quantum-vulnerable* column is the sum of asset findings marked as quantum-vulnerable across all ELF files of the image (`Curve25519`, `DH`, `ECDSA/ECDH`, `RSA`).

| Device / Target | ELF files | AES | ChaCha20 | Crypto-Library | Curve25519 | DH | ECDSA/ECDH | Linux-Kernel-Crypto-API | MD5 | RSA | SHA-1 | SHA-256 | SHA-3 | SHA-512 | TLS | Quantum-vulnerable |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `ath79-generic-8dev_carambola2` | 158 | 2 | 1 | 5 | 1 | 2 | 4 | 3 | 9 | 3 | 4 | 7 | 0 | 6 | 6 | 10 |
| `ath79-nand-aerohive_hiveap-121` | 163 | 2 | 1 | 5 | 1 | 2 | 4 | 3 | 9 | 3 | 4 | 7 | 0 | 6 | 6 | 10 |
| `ipq40xx-generic-8dev_habanero-dvk` | 157 | 2 | 2 | 5 | 1 | 2 | 4 | 2 | 11 | 3 | 4 | 7 | 1 | 6 | 6 | 10 |
| `ipq806x-generic-arris_tr4400-v2` | 173 | 2 | 2 | 5 | 1 | 2 | 4 | 1 | 11 | 3 | 5 | 7 | 1 | 6 | 6 | 10 |
| `kirkwood-generic-checkpoint_l-50` | 164 | 2 | 2 | 5 | 1 | 2 | 4 | 4 | 11 | 3 | 5 | 7 | 1 | 7 | 6 | 10 |
| `lantiq-xrx200-arcadyan_vgv7510kw22-nor` | 179 | 2 | 1 | 5 | 1 | 2 | 4 | 4 | 9 | 3 | 4 | 7 | 0 | 6 | 6 | 10 |
| `mediatek-filogic-acelink_ew-7886cax` | 156 | 2 | 2 | 5 | 1 | 2 | 4 | 3 | 12 | 3 | 6 | 8 | 1 | 6 | 6 | 10 |
| `mediatek-mt7622-bananapi_bpi-r64` | 181 | 2 | 2 | 5 | 1 | 2 | 4 | 0 | 11 | 3 | 4 | 8 | 1 | 6 | 6 | 10 |
| `mvebu-cortexa9-buffalo_ls220de` | 157 | 1 | 2 | 4 | 1 | 2 | 3 | 0 | 11 | 2 | 5 | 8 | 1 | 6 | 5 | 8 |
| `octeon-generic-itus_shield-router` | 135 | 1 | 1 | 4 | 1 | 2 | 3 | 0 | 9 | 2 | 4 | 8 | 0 | 6 | 5 | 8 |
| `ramips-mt7620-aigale_ai-br100` | 159 | 2 | 2 | 5 | 1 | 2 | 4 | 3 | 11 | 3 | 4 | 7 | 1 | 6 | 6 | 10 |
| `ramips-mt7621-adslr_g7` | 155 | 2 | 2 | 5 | 1 | 2 | 4 | 3 | 11 | 3 | 4 | 7 | 1 | 6 | 6 | 10 |
| `ramips-mt76x8-alfa-network_awusfree1` | 147 | 2 | 2 | 5 | 1 | 2 | 4 | 3 | 11 | 3 | 4 | 7 | 1 | 6 | 6 | 10 |
| `ramips-rt305x-allnet_all5002` | 166 | 2 | 2 | 5 | 1 | 2 | 4 | 3 | 11 | 3 | 4 | 7 | 1 | 5 | 6 | 10 |
| `realtek-rtl838x-allnet_all-sg8208m` | 139 | 1 | 1 | 4 | 1 | 2 | 3 | 0 | 7 | 2 | 3 | 6 | 0 | 5 | 5 | 8 |
| `x86-64` | 146 | 2 | 2 | 4 | 1 | 2 | 3 | 0 | 11 | 2 | 4 | 9 | 1 | 7 | 5 | 8 |

## Method

1. **Unpacking:** `cbomscan.py scan-image` detects tarball / `.tar.gz` images as well as `.bin` / `.itb` firmware images, searches for the SquashFS signature (`hsqs`), and unpacks the filesystem with `unsquashfs` into a temporary directory. On case-insensitive filesystems, colliding paths are skipped via `unsquashfs -ll` + `-ef` with a warning.
2. **ELF filtering:** All regular files (excluding symlinks) starting with `\x7fELF` are analyzed individually with `scan()` (excluding non-cryptographic kernel modules `crc32c_generic.ko` and `crypto_null.ko`).
3. **Detection:** For each ELF file, `cbomscan` checks known constants/OIDs, readable ASCII strings, symbol names in `.dynsym` (via `PT_DYNAMIC`) or `.symtab` (for `.ko` modules), and linked library dependencies (`DT_NEEDED`), labeling each asset as *contains* (`enthält`) vs. *uses* (`nutzt`).
4. **Signature & output:** For each ELF file, a CycloneDX 1.6 CBOM together with an Ed25519 signature (`.cbom.json` + `.cbom.json.sig`) is written, as well as a `summary.csv` and `summary.md` per image.

## Limits (honest)

- **Pattern, symbol, and dependency matching only, no disassembly:** No data-flow, control-flow, or code analysis takes place. Statically linked or fully stripped programs without recognizable constants may be missed.
- **“Uses” is a dependency only, not implemented code:** Findings via `DT_NEEDED` (e.g., `Crypto-Library`, `TLS`) only show linkage against a library, not cryptographic code implemented in the binary itself. Counting across all ELF files counts algorithms multiple times across libraries and callers.
- **No runtime or configuration check:** The presence of an algorithm in a library does not prove that it is actually enabled or negotiated in operation.
- **`libubox` MD5:** `MD5` from `libubox` (`md5_begin`/`md5_hash`/`md5_end`) is marked as *checksum, not security-relevant*.
- **Container format limits:** No unpacking of FIT, UBI, or proprietary containers.

## Example CBOMs

Three signed example CBOMs are located under [`results/beispiele/`](beispiele/):
- `ath79_libmbedcrypto.cbom.json` (+ `.sig`)
- `ipq40xx_wpad.cbom.json` (+ `.sig`)
- `x86-64_dropbear.cbom.json` (+ `.sig`)
