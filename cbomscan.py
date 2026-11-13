#!/usr/bin/env python3
"""cbomscan: find cryptography in binaries/firmware, emit a signed CycloneDX 1.6 CBOM
whose every finding carries re-checkable evidence (file hash, byte offset, pattern bytes).

  cbomscan.py scan       <file> -o out.cbom.json [--key key.pem]
  cbomscan.py scan-image <fw_or_dir> -o outdir/ [--key key.pem]
  cbomscan.py verify     out.cbom.json --target <file>
"""
import argparse, base64, csv, hashlib, json, os, re, shutil, subprocess, sys, tarfile, tempfile, uuid
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

H = bytes.fromhex
# (name, family, primitive, qvuln, pattern bytes, note)
SIGS = [
    ("AES", "AES", "block-cipher", False, H("637c777bf26b6fc53001672bfed7ab76"), "forward S-box"),
    ("AES", "AES", "block-cipher", False, H("52096ad53036a538bf40a39e81f3d7fb"), "inverse S-box"),
    ("SHA-256", "SHA-2", "hash", False, H("98 2f 8a 42 91 44 37 71".replace(" ", "")), "round constants K[0..1] LE"),
    ("SHA-256", "SHA-2", "hash", False, H("428a2f9871374491"), "round constants K[0..1] BE"),
    ("SHA-512", "SHA-2", "hash", False, H("428a2f98d728ae22"), "round constants K[0] BE"),
    ("SHA-512", "SHA-2", "hash", False, H("22ae28d7982f8a42"), "round constants K[0] LE"),
    ("SHA-1", "SHA-1", "hash", False, H("0123456789abcdeffedcba9876543210f0e1d2c3"), "init (BE)"),
    ("MD5", "MD5", "hash", False, H("78a46ad756b7c7e8"), "round constants LE"),
    ("SHA-3", "SHA-3", "hash", False, H("0100000000000000" "8280000000000000" "8a80000000000080"), "Keccak round constants LE"),
    ("ChaCha20", "ChaCha", "stream-cipher", False, b"expand 32-byte k", "sigma constant"),
    ("secp256r1", "ECDSA/ECDH", "pke", True, H("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"), "P-256 prime"),
    ("secp256r1", "ECDSA/ECDH", "pke", True, H("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"), "P-256 order"),
    ("secp256k1", "ECDSA/ECDH", "pke", True, H("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"), "secp256k1 prime"),
    ("secp384r1", "ECDSA/ECDH", "pke", True, H("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"), "P-384 prime"),
    ("Curve25519", "EdDSA/X25519", "pke", True, H("ed" + "ff" * 30 + "7f"), "2^255-19 LE"),
    # DER-encoded OIDs (tag 06 + len + value)
    ("RSA", "RSA", "pke", True, H("06092a864886f70d010101"), "OID rsaEncryption"),
    ("ECDSA/ECDH", "EC", "pke", True, H("06072a8648ce3d0201"), "OID id-ecPublicKey"),
    ("secp256r1", "ECDSA/ECDH", "pke", True, H("06082a8648ce3d030107"), "OID prime256v1"),
    ("secp384r1", "ECDSA/ECDH", "pke", True, H("06052b81040022"), "OID secp384r1"),
    ("secp521r1", "ECDSA/ECDH", "pke", True, H("06052b81040023"), "OID secp521r1"),
    ("Ed25519", "EdDSA", "signature", True, H("06032b6570"), "OID Ed25519"),
    ("X25519", "ECDH", "key-agree", True, H("06032b656e"), "OID X25519"),
    ("ML-KEM-512", "ML-KEM", "kem", False, H("0609608648016503040401"), "OID ML-KEM-512"),
    ("ML-KEM-768", "ML-KEM", "kem", False, H("0609608648016503040402"), "OID ML-KEM-768"),
    ("ML-KEM-1024", "ML-KEM", "kem", False, H("0609608648016503040403"), "OID ML-KEM-1024"),
    ("ML-DSA-44", "ML-DSA", "signature", False, H("0609608648016503040311"), "OID ML-DSA-44"),
    ("ML-DSA-65", "ML-DSA", "signature", False, H("0609608648016503040312"), "OID ML-DSA-65"),
    ("ML-DSA-87", "ML-DSA", "signature", False, H("0609608648016503040313"), "OID ML-DSA-87"),
]
# printable-string evidence
STRS = [
    ("RSA", "RSA", "pke", True, rb"TLS_RSA_WITH_[A-Z0-9_]+|rsa_pkcs1_[a-z0-9]+|RSA_PKCS1_[A-Z0-9_]+"),
    ("ECDSA/ECDH", "EC", "pke", True, rb"TLS_ECDHE_[A-Z0-9_]+|ecdsa_secp[0-9a-z]+|ECDSA"),
    ("ML-KEM", "ML-KEM", "kem", False, rb"(?i)ml-?kem[-0-9]*|kyber[-0-9]*|X25519MLKEM768|mlkem[0-9]*"),
    ("ML-DSA", "ML-DSA", "signature", False, rb"(?i)ml-?dsa[-0-9]*|dilithium[-0-9]*"),
    ("SLH-DSA", "SLH-DSA", "signature", False, rb"(?i)slh-?dsa[-a-z0-9]*|sphincs\+?[-a-z0-9]*"),
]
LIBS = re.compile(rb"(OpenSSL [0-9]\.[0-9.]+[a-z]?|libgcrypt [0-9.]+|Libgcrypt version [0-9.]+|mbed TLS [0-9.]+|wolfSSL [0-9.]+|GnuTLS [0-9.]+|libsodium [0-9.]+|BoringSSL|LibreSSL [0-9.]+)", re.I)


def find_all(data, pat, limit=50):
    out, i = [], 0
    while len(out) < limit:
        i = data.find(pat, i)
        if i < 0:
            break
        out.append(i)
        i += 1
    return out


# symbol name -> (asset, family, primitive, quantum-vulnerable)
SYMRULES = [
    (re.compile(r"^(mbedtls_aes_|AES_(set|encrypt|decrypt|cbc)|EVP_aes|wc_Aes|gcry_cipher_)"), "AES", "AES", "block-cipher", False),
    (re.compile(r"^(mbedtls_rsa_|RSA_(new|generate|public|private|sign|verify)|wc_Rsa|EVP_PKEY_RSA)"), "RSA", "RSA", "pke", True),
    (re.compile(r"^(mbedtls_ecdsa_|mbedtls_ecdh_|ECDSA_|ECDH_|EC_KEY_|wc_ecc_)"), "ECDSA/ECDH", "EC", "pke", True),
    (re.compile(r"^(mbedtls_dhm_|DH_(new|generate|compute)|wc_Dh)"), "DH", "DH", "key-agree", True),
    (re.compile(r"(?i)(ed25519|curve25519|x25519)"), "Curve25519", "EdDSA/X25519", "pke", True),
    (re.compile(r"^(mbedtls_chacha20|chacha20_|wc_Chacha)"), "ChaCha20", "ChaCha", "stream-cipher", False),
    (re.compile(r"^(mbedtls_sha256|SHA256_|wc_Sha256)"), "SHA-256", "SHA-2", "hash", False),
    (re.compile(r"^(mbedtls_sha512|SHA512_|wc_Sha512)"), "SHA-512", "SHA-2", "hash", False),
    (re.compile(r"^(mbedtls_sha1|SHA1_|wc_Sha_)"), "SHA-1", "SHA-1", "hash", False),
    (re.compile(r"^(mbedtls_md5|MD5_)"), "MD5", "MD5", "hash", False),
    (re.compile(r"^(mbedtls_ssl_|SSL_(new|connect|accept|CTX_new|read|write)|wolfSSL_(connect|accept)|gnutls_(handshake|init)|tls_)"), "TLS", "TLS", "protocol", None),
    (re.compile(r"(?i)(ml_?kem|kyber|OQS_KEM)"), "ML-KEM", "ML-KEM", "kem", False),
    (re.compile(r"(?i)(ml_?dsa|dilithium|OQS_SIG)"), "ML-DSA", "ML-DSA", "signature", False),
]


def _u(data, off, n, le):
    return int.from_bytes(data[off:off + n], "little" if le else "big")


def elf_dynamic(path):
    """Read the dynamic section through the PROGRAM headers, so it also works on binaries whose
    section headers were removed (sstrip, as in OpenWrt). Returns dict or None."""
    try:
        from elftools.elf.elffile import ELFFile
        data = open(path, "rb").read()
        e = ELFFile(open(path, "rb"))
        le, is64 = e.little_endian, e.elfclass == 64
        loads = [(g["p_vaddr"], g["p_offset"], g["p_filesz"]) for g in e.iter_segments() if g["p_type"] == "PT_LOAD"]
        dyn = next((g for g in e.iter_segments() if g["p_type"] == "PT_DYNAMIC"), None)
        if dyn is None:
            return None
        def off(v):
            for va, fo, sz in loads:
                if va <= v < va + sz:
                    return fo + (v - va)
            return None
        w = 8 if is64 else 4
        tags, needed, o = {}, [], dyn["p_offset"]
        while o + 2 * w <= len(data) and o < dyn["p_offset"] + dyn["p_filesz"]:
            tag, val = _u(data, o, w, le), _u(data, o + w, w, le)
            o += 2 * w
            if tag == 0:
                break
            if tag == 1:
                needed.append(val)
            else:
                tags.setdefault(tag, val)
        return dict(data=data, le=le, is64=is64, tags=tags, needed=needed, off=off, w=w)
    except Exception:
        return None


def _cstr(data, o):
    end = data.find(b"\0", o)
    return data[o:end].decode("ascii", "replace") if end > o else ""


def _symcount(d):
    data, le, off, t = d["data"], d["le"], d["off"], d["tags"]
    if 4 in t and off(t[4]) is not None:  # DT_HASH: nchain == number of symbols
        return _u(data, off(t[4]) + 4, 4, le)
    if 0x6ffffef5 in t and off(t[0x6ffffef5]) is not None:  # DT_GNU_HASH
        g = off(t[0x6ffffef5])
        nb, symoff, bloom = _u(data, g, 4, le), _u(data, g + 4, 4, le), _u(data, g + 8, 4, le)
        bk = g + 16 + bloom * d["w"]
        hi = max((_u(data, bk + 4 * i, 4, le) for i in range(nb)), default=0)
        if hi < symoff:
            return symoff
        ch = bk + 4 * nb
        while _u(data, ch + 4 * (hi - symoff), 4, le) & 1 == 0 and hi < symoff + 100000:
            hi += 1
        return hi + 1
    if 5 in t and 6 in t and off(t[5]) and off(t[6]) and off(t[5]) > off(t[6]):  # strtab after symtab
        return (off(t[5]) - off(t[6])) // (24 if d["is64"] else 16)
    return 0


def elf_symbols(path):
    """Crypto function names in the dynamic symbol table: (asset, family, prim, qvuln, file offset of the name, symbol, defined|imported)."""
    out, d = [], elf_dynamic(path)
    if not d or 5 not in d["tags"] or 6 not in d["tags"]:
        return out
    data, le, off, t = d["data"], d["le"], d["off"], d["tags"]
    st, sy = off(t[5]), off(t[6])
    if st is None or sy is None:
        return out
    ent = 24 if d["is64"] else 16
    seen = set()
    for i in range(min(_symcount(d), 20000)):
        o = sy + i * ent
        if o + ent > len(data):
            break
        nm = _u(data, o, 4, le)
        shndx = _u(data, o + (6 if d["is64"] else 14), 2, le)
        name = _cstr(data, st + nm) if nm else ""
        if not name or name in seen:
            continue
        for rx, asset, fam, prim, qv in SYMRULES:
            if rx.search(name):
                seen.add(name)
                out.append((asset, fam, prim, qv, st + nm, name, "imported" if shndx == 0 else "defined"))
                break
    return out


def elf_needed(path):
    """DT_NEEDED entries with the file offset of each name; works without section headers."""
    d = elf_dynamic(path)
    if not d or 5 not in d["tags"]:
        return []
    st = d["off"](d["tags"][5])
    return [(_cstr(d["data"], st + v), st + v) for v in d["needed"]] if st is not None else []


def elf_info(path):
    """(sections-or-segments, stripped). Falls back to program segments when section headers are gone."""
    try:
        from elftools.elf.elffile import ELFFile
        with open(path, "rb") as fh:
            e = ELFFile(fh)
            secs = [(x["sh_offset"], x["sh_offset"] + x["sh_size"], x.name) for x in e.iter_sections()
                    if x["sh_size"] and x["sh_type"] != "SHT_NOBITS"]
            if not secs:
                segs = []
                for g in e.iter_segments():
                    if g["p_type"] in ("PT_LOAD", "PT_DYNAMIC") and g["p_filesz"]:
                        f = g["p_flags"]
                        segs.append((g["p_offset"], g["p_offset"] + g["p_filesz"],
                                     "segment:%s:%s%s%s" % (g["p_type"][3:], "R" if f & 4 else "-", "W" if f & 2 else "-", "X" if f & 1 else "-")))
                return segs, True
            return secs, e.get_section_by_name(".symtab") is None
    except Exception:
        return [], None


def section_of(secs, off):
    for a, b, n in secs:
        if a <= off < b:
            return n
    return None


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def scan(path):
    data = open(path, "rb").read()
    fhash = hashlib.sha256(data).hexdigest()
    findings = {}  # name -> dict
    def add(name, fam, prim, qv, off, kind, pat_hex, note):
        f = findings.setdefault(name, dict(family=fam, primitive=prim, qvuln=qv, ev=[]))
        f["n"] = f.get("n", 0) + 1
        if kind == "symbol":
            f["imp" if " imported " in note else "def"] = f.get("imp" if " imported " in note else "def", 0) + 1
        if len(f["ev"]) < 8:
            f["ev"].append(dict(offset=off, kind=kind, pattern=pat_hex, note=note))
    for name, fam, prim, qv, pat, note in SIGS:
        for off in find_all(data, pat, 3):
            add(name, fam, prim, qv, off, "bytes", pat.hex(), note)
    for name, fam, prim, qv, rx in STRS:
        n = 0
        for m in re.finditer(rx, data):
            add(name, fam, prim, qv, m.start(), "ascii", m.group(0).hex(), "string " + m.group(0).decode("ascii", "replace")[:40])
            n += 1
            if n >= 3:
                break
    libs = {}
    for m in LIBS.finditer(data):
        libs.setdefault(m.group(0).decode(), (m.start(), m.group(0)))
    for name, fam, prim, qv, off, sym, how in elf_symbols(path):
        add(name, fam, prim, qv, off, "symbol", sym.encode().hex(), "dynsym " + how + " " + sym)
    for need, off in elf_needed(path):
        libs.setdefault("needs " + need, (off, need.encode()))
    secs, stripped = elf_info(path)
    for f in findings.values():
        for e in f["ev"]:
            e["section"] = section_of(secs, e["offset"])
    comps = []
    for name, f in sorted(findings.items()):
        comps.append({
            "type": "cryptographic-asset",
            "bom-ref": "crypto/" + name.replace("/", "-"),
            "name": name,
            "cryptoProperties": ({"assetType": "protocol", "protocolProperties": {"type": "tls"}} if f["primitive"] == "protocol" else {
                "assetType": "algorithm",
                "algorithmProperties": {"primitive": f["primitive"]},
            }),
            "properties": [{"name": "cbomscan:quantum-vulnerable", "value": "unknown" if f["qvuln"] is None else str(f["qvuln"]).lower()},
                           {"name": "cbomscan:family", "value": f["family"]},
                           {"name": "cbomscan:matches-total", "value": str(f.get("n", 0))},
                           {"name": "cbomscan:evidence-listed", "value": str(len(f["ev"]))},
                           {"name": "cbomscan:symbols-imported", "value": str(f.get("imp", 0))},
                           {"name": "cbomscan:symbols-defined", "value": str(f.get("def", 0))}],
            "evidence": {"occurrences": [
                {"location": os.path.basename(path), "offset": e["offset"],
                 "additionalContext": json.dumps({"kind": e["kind"], "pattern_hex": e["pattern"], "note": e["note"], "elf_section": e["section"]})}
                for e in f["ev"]]},
        })
    for lib, (off, raw) in libs.items():
        comps.append({"type": "library", "name": lib, "bom-ref": "lib/" + lib.replace(" ", "-"),
                      "evidence": {"occurrences": [{"location": os.path.basename(path), "offset": off,
                                   "additionalContext": json.dumps({"kind": "ascii", "pattern_hex": raw.hex(), "note": "library string or DT_NEEDED"})}]}})
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                     "tools": {"components": [{"type": "application", "name": "cbomscan", "version": "0.5"}]},
                     "properties": [{"name": "cbomscan:elf-stripped", "value": str(stripped).lower()}],
                     "component": {"type": "file", "name": os.path.basename(path), "bom-ref": "target",
                                   "hashes": [{"alg": "SHA-256", "content": fhash}]}},
        "components": comps,
    }
    return bom


def load_key(p):
    if os.path.exists(p):
        return serialization.load_pem_private_key(open(p, "rb").read(), None)
    k = Ed25519PrivateKey.generate()
    open(p, "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return k


def write_signed_cbom(bom, out_path, key_path):
    """Write a CycloneDX CBOM and its detached Ed25519 signature."""
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w") as fh:
        json.dump(bom, fh, indent=1)
    k = load_key(key_path)
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sig = k.sign(canon(bom))
    with open(out_path + ".sig", "w") as fh:
        json.dump({"alg": "Ed25519", "publicKey": base64.b64encode(pub).decode(),
                   "signature": base64.b64encode(sig).decode(), "signs": "canonical JSON of the CBOM"},
                  fh, indent=1)


def _cbom_summary(bom):
    assets = [c for c in bom["components"] if c["type"] == "cryptographic-asset"]
    vuln = [c["name"] for c in assets
            if any(p["name"] == "cbomscan:quantum-vulnerable" and p["value"] == "true" for p in c["properties"])]
    needs = [c["name"][6:] for c in bom["components"] if c["type"] == "library" and c["name"].startswith("needs ")]
    return assets, vuln, needs


def cmd_scan(a):
    bom = scan(a.file)
    write_signed_cbom(bom, a.o, a.key)
    assets, vuln, _ = _cbom_summary(bom)
    print(f"{a.file}: {len(assets)} crypto assets, quantum-vulnerable: {', '.join(vuln) or 'none found'}")


def _unsquashfs(img_path, dest_dir):
    """Find SquashFS magic in img_path and unpack it with unsquashfs."""
    with open(img_path, "rb") as fh:
        data = fh.read()
    off = data.find(b"hsqs")
    if off < 0:
        return False
    if shutil.which("unsquashfs") is None:
        raise RuntimeError("unsquashfs not found in PATH")
    subprocess.run(["unsquashfs", "-q", "-o", str(off), "-d", dest_dir, img_path],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return os.path.isdir(dest_dir) and any(True for _ in os.walk(dest_dir))


def _extract_image(target, tmpdir):
    """Return directory to scan: target itself if a dir, or unpacked firmware root inside tmpdir."""
    if os.path.isdir(target):
        return target
    fs_dir = os.path.join(tmpdir, "fs")
    if tarfile.is_tarfile(target):
        tar_dir = os.path.join(tmpdir, "tar")
        os.makedirs(tar_dir, exist_ok=True)
        with tarfile.open(target, "r:*") as tf:
            for m in tf.getmembers():
                if not m.isfile():
                    continue
                rel = os.path.normpath(m.name).lstrip("/")
                if rel.startswith("..") or os.path.isabs(rel):
                    continue
                out_p = os.path.join(tar_dir, rel)
                os.makedirs(os.path.dirname(out_p), exist_ok=True)
                with tf.extractfile(m) as src, open(out_p, "wb") as dst:
                    shutil.copyfileobj(src, dst)
        for root_dir, _, files in os.walk(tar_dir):
            if "root" in files:
                cand = os.path.join(root_dir, "root")
                if _unsquashfs(cand, fs_dir):
                    return fs_dir
        return tar_dir
    if _unsquashfs(target, fs_dir):
        return fs_dir
    raise RuntimeError(f"cannot unpack firmware image: {target}")


def iter_elf_files(root_dir):
    """Yield (relpath, fullpath) for all non-symlink ELF files under root_dir."""
    paths = []
    for r, _, files in os.walk(root_dir, followlinks=False):
        for fn in files:
            p = os.path.join(r, fn)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            try:
                with open(p, "rb") as fh:
                    if fh.read(4) == b"\x7fELF":
                        paths.append((os.path.relpath(p, root_dir), p))
            except OSError:
                continue
    return sorted(paths)


def cmd_scan_image(a):
    os.makedirs(a.o, exist_ok=True)
    cbom_dir = os.path.join(a.o, "cboms")
    os.makedirs(cbom_dir, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmpdir:
        scan_root = _extract_image(a.target, tmpdir)
        elfs = iter_elf_files(scan_root)
        rows = []
        alg_counts = {}
        qvuln_counts = {}
        for rel, full in elfs:
            bom = scan(full)
            safe_name = rel.replace(os.sep, "__").replace(" ", "_") + ".cbom.json"
            cbom_path = os.path.join(cbom_dir, safe_name)
            write_signed_cbom(bom, cbom_path, a.key)
            assets, vuln, needs = _cbom_summary(bom)
            for c in assets:
                alg_counts[c["name"]] = alg_counts.get(c["name"], 0) + 1
            for q in vuln:
                qvuln_counts[q] = qvuln_counts.get(q, 0) + 1
            rows.append({
                "file": rel,
                "crypto_assets": len(assets),
                "algorithms": "; ".join(c["name"] for c in assets),
                "quantum_vulnerable_count": len(vuln),
                "quantum_vulnerable": "; ".join(vuln),
                "needs": "; ".join(needs),
                "cbom_file": os.path.join("cboms", safe_name),
            })
    csv_path = os.path.join(a.o, "summary.csv")
    with open(csv_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["file", "crypto_assets", "algorithms", "quantum_vulnerable_count", "quantum_vulnerable", "needs", "cbom_file"])
        w.writeheader()
        w.writerows(rows)
    md_path = os.path.join(a.o, "summary.md")
    target_name = os.path.basename(os.path.abspath(a.target))
    lines = [
        f"# cbomscan image summary: `{target_name}`",
        "",
        f"- ELF files scanned: **{len(elfs)}**",
        f"- ELF files with crypto findings: **{sum(1 for r in rows if r['crypto_assets'] > 0)}**",
        f"- Algorithm counts (files): {', '.join(f'{k}: {v}' for k, v in sorted(alg_counts.items())) or 'none'}",
        f"- Quantum-vulnerable counts (files): {', '.join(f'{k}: {v}' for k, v in sorted(qvuln_counts.items())) or 'none'}",
        "",
        "| File | Crypto assets | Algorithms | Quantum-vulnerable | Needs |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        if r["crypto_assets"] > 0 or r["needs"]:
            lines.append(f"| `{r['file']}` | {r['crypto_assets']} | {r['algorithms'] or '–'} | {r['quantum_vulnerable'] or '–'} | {r['needs'] or '–'} |")
    with open(md_path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"{target_name}: {len(elfs)} ELF files, {sum(1 for r in rows if r['crypto_assets'] > 0)} with crypto, summary in {a.o}")


def cmd_verify(a):
    bom = json.load(open(a.cbom))
    s = json.load(open(a.cbom + ".sig"))
    ok = True
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(s["publicKey"])).verify(base64.b64decode(s["signature"]), canon(bom))
        print("signature: OK")
    except Exception:
        print("signature: INVALID"); ok = False
    data = open(a.target, "rb").read()
    want = bom["metadata"]["component"]["hashes"][0]["content"]
    if hashlib.sha256(data).hexdigest() != want:
        print("target hash: MISMATCH"); ok = False
    else:
        print("target hash: OK")
    bad = tot = 0
    for c in bom["components"]:
        for o in c.get("evidence", {}).get("occurrences", []):
            ctx = o.get("additionalContext")
            if not ctx:
                continue
            ctx = json.loads(ctx); pat = bytes.fromhex(ctx["pattern_hex"]); tot += 1
            if data[o["offset"]:o["offset"] + len(pat)] != pat:
                bad += 1; print("evidence FAIL:", c["name"], o["offset"])
    print(f"evidence: {tot - bad}/{tot} re-checked against the bytes")
    sys.exit(0 if ok and bad == 0 else 1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="c", required=True)
    s = sp.add_parser("scan"); s.add_argument("file"); s.add_argument("-o", required=True); s.add_argument("--key", default="signing.pem"); s.set_defaults(f=cmd_scan)
    si = sp.add_parser("scan-image"); si.add_argument("target"); si.add_argument("-o", required=True); si.add_argument("--key", default="signing.pem"); si.set_defaults(f=cmd_scan_image)
    v = sp.add_parser("verify"); v.add_argument("cbom"); v.add_argument("--target", required=True); v.set_defaults(f=cmd_verify)
    a = ap.parse_args(); a.f(a)
