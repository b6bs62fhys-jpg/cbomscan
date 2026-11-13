# Evaluation: 16 OpenWrt 23.05.5 Images (`cbomscan scan-image`)

Scan of 16 public release images (OpenWrt 23.05.5, obtained from `downloads.openwrt.org`) across different architectures and target platforms using `cbomscan.py scan-image`.
This is a feasibility probe on 16 OpenWrt images and makes no statement about vendor firmware. The *Quantum-vulnerable* column is a sum of findings across files, not the number of distinct vulnerabilities.

## Results per device

The per-algorithm columns count in **how many ELF files** of the respective image the algorithm was found. The *Quantum-vulnerable* column is the sum of asset findings marked as quantum-vulnerable across all ELF files of the image (`Curve25519`, `DH`, `ECDSA/ECDH`, `RSA`).

| Device / Target | ELF files | AES | ChaCha20 | Curve25519 | DH | ECDSA/ECDH | MD5 | RSA | SHA-1 | SHA-256 | SHA-3 | SHA-512 | TLS | Quantum-vulnerable |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `ath79-generic-8dev_carambola2` | 158 | 2 | 1 | 1 | 2 | 4 | 3 | 3 | 4 | 7 | 0 | 6 | 2 | 10 |
| `ath79-nand-aerohive_hiveap-121` | 163 | 2 | 1 | 1 | 2 | 4 | 3 | 3 | 4 | 7 | 0 | 6 | 2 | 10 |
| `ipq40xx-generic-8dev_habanero-dvk` | 157 | 2 | 2 | 1 | 2 | 4 | 5 | 3 | 4 | 7 | 1 | 6 | 2 | 10 |
| `ipq806x-generic-arris_tr4400-v2` | 173 | 2 | 2 | 1 | 2 | 4 | 5 | 3 | 5 | 7 | 1 | 6 | 2 | 10 |
| `kirkwood-generic-checkpoint_l-50` | 164 | 2 | 2 | 1 | 2 | 4 | 5 | 3 | 5 | 7 | 1 | 7 | 2 | 10 |
| `lantiq-xrx200-arcadyan_vgv7510kw22-nor` | 179 | 2 | 1 | 1 | 2 | 4 | 3 | 3 | 4 | 7 | 0 | 6 | 2 | 10 |
| `mediatek-filogic-acelink_ew-7886cax` | 156 | 2 | 2 | 1 | 2 | 4 | 5 | 3 | 4 | 6 | 1 | 5 | 2 | 10 |
| `mediatek-mt7622-bananapi_bpi-r64` | 181 | 2 | 2 | 1 | 2 | 4 | 5 | 3 | 4 | 7 | 1 | 6 | 2 | 10 |
| `mvebu-cortexa9-buffalo_ls220de` | 157 | 1 | 2 | 1 | 2 | 3 | 5 | 2 | 5 | 8 | 1 | 6 | 2 | 8 |
| `octeon-generic-itus_shield-router` | 135 | 1 | 1 | 1 | 2 | 3 | 3 | 2 | 4 | 7 | 0 | 6 | 2 | 8 |
| `ramips-mt7620-aigale_ai-br100` | 159 | 2 | 2 | 1 | 2 | 4 | 5 | 3 | 4 | 7 | 1 | 6 | 2 | 10 |
| `ramips-mt7621-adslr_g7` | 155 | 2 | 2 | 1 | 2 | 4 | 5 | 3 | 4 | 7 | 1 | 6 | 2 | 10 |
| `ramips-mt76x8-alfa-network_awusfree1` | 147 | 2 | 2 | 1 | 2 | 4 | 5 | 3 | 4 | 7 | 1 | 6 | 2 | 10 |
| `ramips-rt305x-allnet_all5002` | 166 | 2 | 2 | 1 | 2 | 4 | 5 | 3 | 4 | 7 | 1 | 5 | 2 | 10 |
| `realtek-rtl838x-allnet_all-sg8208m` | 139 | 1 | 1 | 1 | 2 | 3 | 2 | 2 | 3 | 6 | 0 | 5 | 2 | 8 |
| `x86-64` | 146 | 2 | 2 | 1 | 2 | 3 | 5 | 2 | 4 | 8 | 1 | 7 | 2 | 8 |

## Method

1. **Unpacking:** `cbomscan.py scan-image` detects tarball / `.tar.gz` images as well as `.bin` / `.itb` firmware images, searches the image (or a `root` blob inside it) for the SquashFS signature (`hsqs`), and unpacks the filesystem with `unsquashfs` into a temporary directory.
2. **ELF filtering:** All regular files (excluding symlinks) starting with `\x7fELF` are analyzed individually with `scan()`.
3. **Detection:** For each ELF file, `cbomscan` checks three sources:
   - known constants, S-boxes, curve primes, and DER OIDs in the bytes,
   - readable ASCII strings (e.g., cipher suite names, library strings),
   - names in the dynamic symbol table (`.dynsym`) as well as linked libraries (`DT_NEEDED`) via the program headers (`PT_DYNAMIC`), so that OpenWrt binaries stripped with `sstrip` without section headers are also evaluated.
4. **Signature & output:** For each ELF file, a CycloneDX 1.6 CBOM together with an Ed25519 signature (`.cbom.json` + `.cbom.json.sig`) is written, as well as a `summary.csv` and `summary.md` per image.

## Limits (honest)

- **Pattern and symbol matching only, no disassembly:** No data-flow, control-flow, or code analysis takes place. Algorithms without known constants and without recognizable symbol names (e.g., hand-written assembly or statically linked, fully stripped binaries) are not detected.
- **Imports show usage, not implementation:** For programs such as `wpad`, hits (e.g., `AES`, `RSA`, `ECDSA/ECDH`) come from imported symbols (`SHN_UNDEF`) of the linked library `libmbedcrypto` — not from cryptographic code implemented inside `wpad` itself. Counting across all ELF files therefore counts the same algorithm multiple times (once in the library and once in the callers).
- **No runtime or configuration check:** The presence of an algorithm in a library does not prove that it is actually enabled or negotiated in operation.
- **Sample instead of full evidence:** At most 8 byte or symbol evidence entries are stored per asset in the CBOM.
- **Platform note on `unsquashfs`:** On macOS without root privileges, creating device nodes (`/dev/console`) fails with exit code 2; all regular ELF files are still unpacked and scanned completely.

## Example CBOMs

Three signed example CBOMs from this run are located under [`results/beispiele/`](beispiele/):
- `ath79_libmbedcrypto.cbom.json` (+ `.sig`)
- `ipq40xx_wpad.cbom.json` (+ `.sig`)
- `x86-64_dropbear.cbom.json` (+ `.sig`)
