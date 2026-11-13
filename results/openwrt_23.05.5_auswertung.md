# Auswertung: 16 OpenWrt-23.05.5-Images (`cbomscan` v0.7 `scan-image`)

> **Hinweis:** Eine frühere Fassung (v0.5) hat weniger Funde gezeigt; die Erkennung wurde in v0.7 erweitert (u. a. `DT_NEEDED`-Abhängigkeiten, `.ko`-Kernel-Module, Ausschluss von `crc32c_generic.ko`/`crypto_null.ko`, Kennzeichnung von `libubox`-MD5 und Trennung in *enthält* vs. *nutzt*). Die ELF-Gesamtzahlen sind unverändert.

Scan von 16 öffentlichen Release-Images (OpenWrt 23.05.5, bezogen von `downloads.openwrt.org`) über verschiedene Architekturen und Zielplattformen hinweg mit `cbomscan.py scan-image` (v0.7).

## Ergebnisse je Gerät

Die Spalten pro Algorithmus zählen, in **wie vielen ELF-Dateien** des jeweiligen Images der Algorithmus gefunden wurde (Summe aus *enthält* und *nutzt*). Die Spalte *Quantenanfällig* ist die Summe der als quantenanfällig markierten Asset-Funde über alle ELF-Dateien des Images (`Curve25519`, `DH`, `ECDSA/ECDH`, `RSA`).

| Gerät / Target | ELF-Dateien | AES | ChaCha20 | Crypto-Library | Curve25519 | DH | ECDSA/ECDH | Linux-Kernel-Crypto-API | MD5 | RSA | SHA-1 | SHA-256 | SHA-3 | SHA-512 | TLS | Quantenanfällig |
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

## Methode

1. **Entpacken:** `cbomscan.py scan-image` erkennt Tarball-/`.tar.gz`-Images sowie `.bin`/`.itb`-Firmware-Images, sucht im Image (oder im darin enthaltenen `root`-Blob) die SquashFS-Signatur (`hsqs`) und entpackt das Dateisystem mit `unsquashfs` in ein temporäres Verzeichnis. Auf Dateisystemen ohne Groß-/Kleinschreibungs-Unterscheidung werden kollidierende Pfade über `unsquashfs -ll` + `-ef` übersprungen und mit Warnung gemeldet.
2. **ELF-Filterung:** Alle regulären Dateien (ohne Symlinks), die mit `\x7fELF` beginnen, werden einzeln mit `scan()` analysiert (mit Ausnahme der nicht-kryptografischen Kernel-Module `crc32c_generic.ko` und `crypto_null.ko`).
3. **Erkennung:** Für jede ELF-Datei prüft `cbomscan` bekannte Konstanten/OIDs, lesbare ASCII-Strings, Symbolnamen in `.dynsym` (über `PT_DYNAMIC`) bzw. `.symtab` (für `.ko`-Module) sowie Bibliotheksabhängigkeiten (`DT_NEEDED`) und kennzeichnet je Asset *enthält* vs. *nutzt*.
4. **Signatur & Ausgabe:** Für jede ELF-Datei wird ein CycloneDX-1.6-CBOM samt Ed25519-Signatur (`.cbom.json` + `.cbom.json.sig`) sowie pro Image eine `summary.csv` und `summary.md` geschrieben.

## Grenzen (ehrlich)

- **Nur Muster-, Symbol- und Abhängigkeits-Erkennung, keine Disassemblierung:** Es findet keine Datenfluss-, Kontrollfluss- oder Codeanalyse statt. Statisch gelinkte oder vollständig gestrippte Programme ohne bekannte Konstanten können fehlen.
- **„nutzt“ ist nur eine Abhängigkeit, kein eigener Code:** Einträge über `DT_NEEDED` (z. B. `Crypto-Library`, `TLS`) zeigen nur die Verlinkung gegen eine Bibliothek, nicht eigenen Krypto-Code. Auch bei importierten Symbolen wird derselbe Algorithmus über Bibliothek und Aufrufer mehrfach gezählt.
- **Keine Laufzeit- oder Konfigurationsprüfung:** Dass ein Algorithmus in einer Bibliothek vorhanden ist, beweist nicht, dass er im Betrieb aktiviert oder ausgehandelt wird.
- **`libubox`-MD5:** `MD5` aus `libubox` (`md5_begin`/`md5_hash`/`md5_end`) ist als *Prüfsumme, nicht sicherheitsrelevant genutzt* gekennzeichnet.
- **Container-Formatgrenzen:** Kein Entpacken von FIT-, UBI- und proprietären Containern.

## Beispiel-CBOMs

Unter [`results/beispiele/`](beispiele/) liegen drei signierte Beispiel-CBOMs:
- `ath79_libmbedcrypto.cbom.json` (+ `.sig`)
- `ipq40xx_wpad.cbom.json` (+ `.sig`)
- `x86-64_dropbear.cbom.json` (+ `.sig`)
