# Auswertung: 16 OpenWrt-23.05.5-Images (`cbomscan scan-image`)

Scan von 16 öffentlichen Release-Images (OpenWrt 23.05.5, bezogen von `downloads.openwrt.org`) über verschiedene Architekturen und Zielplattformen hinweg mit `cbomscan.py scan-image`.

## Ergebnisse je Gerät

Die Spalten pro Algorithmus zählen, in **wie vielen ELF-Dateien** des jeweiligen Images der Algorithmus gefunden wurde. Die Spalte *Quantenanfällig* ist die Summe der als quantenanfällig markierten Asset-Funde über alle ELF-Dateien des Images (`Curve25519`, `DH`, `ECDSA/ECDH`, `RSA`).

| Gerät / Target | ELF-Dateien | AES | ChaCha20 | Curve25519 | DH | ECDSA/ECDH | MD5 | RSA | SHA-1 | SHA-256 | SHA-3 | SHA-512 | TLS | Quantenanfällig |
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

## Methode

1. **Entpacken:** `cbomscan.py scan-image` erkennt Tarball-/`.tar.gz`-Images sowie `.bin`/`.itb`-Firmware-Images, sucht im Image (oder im darin enthaltenen `root`-Blob) die SquashFS-Signatur (`hsqs`) und entpackt das Dateisystem mit `unsquashfs` in ein temporäres Verzeichnis.
2. **ELF-Filterung:** Alle regulären Dateien (ohne Symlinks), die mit `\x7fELF` beginnen, werden einzeln mit `scan()` analysiert.
3. **Erkennung:** Für jede ELF-Datei prüft `cbomscan` drei Quellen:
   - bekannte Konstanten, S-Boxen, Kurven-Primzahlen und DER-OIDs in den Bytes,
   - lesbare ASCII-Zeichenketten (z. B. Cipher-Suite-Namen, Bibliotheksstrings),
   - Namen in der dynamischen Symboltabelle (`.dynsym`) sowie verlinkte Bibliotheken (`DT_NEEDED`) über die Program-Header (`PT_DYNAMIC`), sodass auch mit `sstrip` gestrippte OpenWrt-Binaries ohne Section-Header ausgewertet werden.
4. **Signatur & Ausgabe:** Für jede ELF-Datei wird ein CycloneDX-1.6-CBOM samt Ed25519-Signatur (`.cbom.json` + `.cbom.json.sig`) sowie pro Image eine `summary.csv` und `summary.md` geschrieben.

## Grenzen (ehrlich)

- **Nur Muster- und Symbolerkennung, keine Disassemblierung:** Es findet keine Datenfluss-, Kontrollfluss- oder Codeanalyse statt. Algorithmen ohne bekannte Konstanten und ohne erkennbare Symbolnamen (z. B. handgeschriebener Assembler oder statisch gelinkte, vollständig gestrippte Binaries) werden nicht erkannt.
- **Importe zeigen Nutzung, nicht Implementierung:** Bei Programmen wie `wpad` stammen Treffer (z. B. `AES`, `RSA`, `ECDSA/ECDH`) aus importierten Symbolen (`SHN_UNDEF`) der verlinkten Bibliothek `libmbedcrypto` — nicht aus eigenem Krypto-Code in `wpad`. Die Zählung über alle ELF-Dateien zählt denselben Algorithmus also mehrfach (einmal in der Bibliothek und einmal in den Aufrufern).
- **Keine Laufzeit- oder Konfigurationsprüfung:** Dass ein Algorithmus in einer Bibliothek vorhanden ist, beweist nicht, dass er im Betrieb tatsächlich aktiviert oder ausgehandelt wird.
- **Stichprobe statt Vollbeleg:** Pro Asset werden maximal 8 Byte-/Symbol-Belege im CBOM gespeichert.
- **Plattform-Hinweis zu `unsquashfs`:** Auf macOS ohne Root-Rechte schlägt das Anlegen von Gerätedateien (`/dev/console`) mit Exit-Code 2 fehl; alle regulären ELF-Dateien werden dennoch vollständig entpackt und gescannt.

## Beispiel-CBOMs

Unter [`results/beispiele/`](beispiele/) liegen drei signierte Beispiel-CBOMs aus diesem Lauf:
- `ath79_libmbedcrypto.cbom.json` (+ `.sig`)
- `ipq40xx_wpad.cbom.json` (+ `.sig`)
- `x86-64_dropbear.cbom.json` (+ `.sig`)
