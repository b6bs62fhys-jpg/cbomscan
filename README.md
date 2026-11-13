# cbomscan

Finds cryptography in compiled software and firmware and writes a signed CycloneDX 1.6 CBOM.
Every finding carries evidence anyone can re-check against the original bytes: file hash, byte offset, matched pattern, ELF section.

    pip install -r requirements.txt
    python cbomscan.py scan libfoo.so -o libfoo.cbom.json      # also writes libfoo.cbom.json.sig (Ed25519)
    python cbomscan.py verify libfoo.cbom.json --target libfoo.so

`verify` checks the signature, the target hash, and re-reads every evidence offset in the target file.
A changed CBOM or a changed binary fails. Keep `signing.pem` private; it is created on the first scan and is never meant to be committed.

## What it finds
- Algorithm constants and tables: AES, SHA-1/2/3, MD5, ChaCha20, curve primes and DER OIDs for RSA, EC, Ed25519, X25519, ML-KEM, ML-DSA.
- Function names in the dynamic symbol table (mbedtls_aes_*, RSA_*, TLS entry points), counted as defined or imported.
- Shared libraries a binary links against (DT_NEEDED).
- Works on binaries without section headers (stripped firmware): symbols and links are read from the program headers.
- Each asset is flagged quantum-vulnerable (RSA, EC, DH, Ed25519, X25519), not, or unknown (protocols).

## Measured so far (prototype, v0.5)
Five OpenWrt 23.05.5 images (TP-Link WR841N v13, Archer C7 v2, Xiaomi Mi Router 4A, GL.iNet GL-B1300, x86-64), unpacked with unsquashfs.
39 ELF files that ship or use crypto (dropbear, libmbed*, libustream-ssl, uhttpd, wpad).

- All 39 scans ran, all 39 verify OK.
- mbedTLS libraries: RSA, ECDSA/ECDH, DH, AES, ChaCha20, MD5, SHA-1/256/512 found with evidence. dropbear: SHA-256/512, ChaCha20. wpad: AES, ECDSA/ECDH, RSA (imported from libmbedcrypto, not implemented in wpad).
- An earlier version found nothing through symbols because these files have no section headers. That is fixed. An earlier SHA-1 pattern also matched MD5; removed.
- CBOMkit (source code scanner) cannot scan binaries. CBOMkit-theia (directory scanner) reports certificates and keys only: no algorithm findings, and 2 false alarms (PEM header strings) per libmbedcrypto.

## Limits
- Pattern and symbol based. No disassembly, no firmware unpacking, no function level attribution in fully stripped static binaries.
- Cryptography that exists only as code immediates (hand written assembler) is not found.
- Imported symbols show that a binary uses a function, not that it contains the implementation.
- Not benchmarked against commercial binary scanners. The ground truth used so far shares its method (symbol names) with the scanner, so it does not prove completeness.
- The signature proves who issued the CBOM and that it was not changed. It does not prove the scan was complete.

Test: `python -m pytest` (the section header test needs Linux and gcc).
License: MIT.

## Beispiel
Ein signiertes Beispiel-CBOM aus dem OpenWrt-23.05.5-Image (TP-Link Archer C7 v2, `libmbedcrypto.so.2.28.9`) inklusive Verifikationsanleitung liegt unter [examples/openwrt_beispiel.md](examples/openwrt_beispiel.md).

Batch evaluation of 16 OpenWrt 23.05.5 images (`scan-image`): [results/openwrt_23.05.5_summary_en.md](results/openwrt_23.05.5_summary_en.md) (German: [results/openwrt_23.05.5_auswertung.md](results/openwrt_23.05.5_auswertung.md)).
