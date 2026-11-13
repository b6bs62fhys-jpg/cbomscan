# Beispiel: OpenWrt 23.05.5 (TP-Link Archer C7 v2)

Scan von `usr/lib/libmbedcrypto.so.2.28.9` aus `openwrt-23.05.5-ath79-generic-tplink_archer-c7-v2-squashfs-sysupgrade.bin` mit `cbomscan` v0.5.

- **Zieldatei:** `usr/lib/libmbedcrypto.so.2.28.9` (SHA-256: `e251f41e13a2ce8e9024cf637f3dc5fbd099fb21aa4932829212dbb4437e47bb`)
- **Signiertes CBOM:** [archer_c7_libmbedcrypto.cbom.json](archer_c7_libmbedcrypto.cbom.json)
- **Signaturdatei:** [archer_c7_libmbedcrypto.cbom.json.sig](archer_c7_libmbedcrypto.cbom.json.sig)
- **Öffentlicher Schlüssel (Ed25519, Base64):** `36MJNeyWU2w2rK69vDBFnDA5TrVZrpKZ96wld52LZ5M=`

## Befunde

`cbomscan` findet **9** Krypto-Assets, davon **3 quantenanfällig** (`DH`, `ECDSA/ECDH`, `RSA`), sowie **2** `DT_NEEDED`-Abhängigkeiten (`libgcc_s.so.1`, `libc.so`), insgesamt 72 überprüfbare Byte-Belege:

| Asset | Quantenanfällig | Belege | Beispiel-Offset |
|---|---|---|---|
| `AES` | nein (`false`) | 8 | 17156 |
| `ChaCha20` | nein (`false`) | 6 | 20084 |
| `DH` | **ja (`true`)** | 8 | 22812 |
| `ECDSA/ECDH` | **ja (`true`)** | 8 | 319510 |
| `MD5` | nein (`false`) | 8 | 26232 |
| `RSA` | **ja (`true`)** | 8 | 27776 |
| `SHA-1` | nein (`false`) | 8 | 26374 |
| `SHA-256` | nein (`false`) | 8 | 334812 |
| `SHA-512` | nein (`false`) | 8 | 335072 |

## Nachprüfen mit `cbomscan verify`

Nach dem Entpacken von `openwrt-23.05.5-ath79-generic-tplink_archer-c7-v2-squashfs-sysupgrade.bin` (z. B. mit `unsquashfs`):

```bash
python cbomscan.py verify examples/archer_c7_libmbedcrypto.cbom.json \
  --target <pfad-zur-entpackten-firmware>/usr/lib/libmbedcrypto.so.2.28.9
```

Erwartete Ausgabe:

```text
signature: OK
target hash: OK
evidence: 72/72 re-checked against the bytes
```
