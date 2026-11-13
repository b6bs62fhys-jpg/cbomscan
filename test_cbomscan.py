import json, os, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__)); S = os.path.join(HERE, "cbomscan.py")
def run(*a): return subprocess.run([sys.executable, "-I", S, *a], capture_output=True, text=True)
def test_roundtrip_and_tamper():
    d = tempfile.mkdtemp(); t = os.path.join(d, "fw.bin"); o = os.path.join(d, "o.json"); k = os.path.join(d, "k.pem")
    blob = b"\x00" * 64 + bytes.fromhex("06092a864886f70d010101") + b"\x00" * 32 + bytes.fromhex("0609608648016503040402") + b"\x00" * 16
    open(t, "wb").write(blob)
    assert run("scan", t, "-o", o, "--key", k).returncode == 0
    names = {c["name"] for c in json.load(open(o))["components"]}
    assert {"RSA", "ML-KEM-768"} <= names and "AES" not in names
    assert run("verify", o, "--target", t).returncode == 0
    open(t, "wb").write(blob.replace(bytes.fromhex("2a864886f70d010101"), b"\x11" * 9))
    assert run("verify", o, "--target", t).returncode != 0  # target changed -> must fail
def test_cbom_edit_detected():
    d = tempfile.mkdtemp(); t = os.path.join(d, "f"); o = os.path.join(d, "o.json"); k = os.path.join(d, "k.pem")
    open(t, "wb").write(bytes.fromhex("06092a864886f70d010101"))
    run("scan", t, "-o", o, "--key", k)
    s = open(o).read().replace('"rsaEncryption"', 'x'); b = json.load(open(o)); b["components"][0]["name"] = "AES"; json.dump(b, open(o, "w"))
    assert run("verify", o, "--target", t).returncode != 0

import shutil, pytest
@pytest.mark.skipif(sys.platform != "linux" or shutil.which("gcc") is None, reason="needs Linux gcc (ELF output)")
def test_works_without_section_headers():
    """Firmware builds (e.g. OpenWrt sstrip) drop section headers; symbols and DT_NEEDED must still be found."""
    d = tempfile.mkdtemp(); c = os.path.join(d, "a.c"); so = os.path.join(d, "liba.so"); o = os.path.join(d, "o.json"); k = os.path.join(d, "k.pem")
    open(c, "w").write("int mbedtls_aes_setkey_enc(void*a){return 0;}\nint mbedtls_rsa_pkcs1_sign(void*a){return 0;}\n")
    assert subprocess.run(["gcc", "-shared", "-fPIC", "-Wl,--no-as-needed", "-o", so, c, "-lm"]).returncode == 0
    b = bytearray(open(so, "rb").read())
    b[0x28:0x30] = b"\0" * 8; b[0x3a:0x40] = b"\0" * 6   # e_shoff, e_shentsize, e_shnum, e_shstrndx
    open(so, "wb").write(b)
    assert run("scan", so, "-o", o, "--key", k).returncode == 0
    names = {x["name"] for x in json.load(open(o))["components"]}
    assert {"AES", "RSA"} <= names and "needs libm.so.6" in names
    assert run("verify", o, "--target", so).returncode == 0

def test_scan_image_dir():
    d = tempfile.mkdtemp(); sub = os.path.join(d, "usr", "lib"); os.makedirs(sub)
    elf = os.path.join(sub, "libcrypto.so"); non = os.path.join(sub, "readme.txt"); out = os.path.join(d, "out"); k = os.path.join(d, "k.pem")
    open(elf, "wb").write(b"\x7fELF" + b"\x00" * 60 + bytes.fromhex("06092a864886f70d010101"))
    open(non, "wb").write(b"not an elf " + bytes.fromhex("06092a864886f70d010101"))
    assert run("scan-image", d, "-o", out, "--key", k).returncode == 0
    assert os.path.exists(os.path.join(out, "summary.csv"))
    assert os.path.exists(os.path.join(out, "summary.md"))
    cbom = os.path.join(out, "cboms", "usr__lib__libcrypto.so.cbom.json")
    assert os.path.exists(cbom) and os.path.exists(cbom + ".sig")
    assert run("verify", cbom, "--target", elf).returncode == 0

def test_strongswan_and_kernel_rules():
    import sys as _sys
    _sys.path.insert(0, HERE)
    import cbomscan
    for sym, want in [
        ("aes_crypter_create", "AES"),
        ("des_crypter_create", "DES"),
        ("hmac_plugin_create", "HMAC"),
        ("x509_cert_load", "X.509"),
        ("libcharon_init", "IPsec/IKEv2"),
        ("chacha_crypt_arch", "ChaCha20"),
        ("poly1305_init_arch", "Poly1305"),
        ("crypto_register_skciphers", "Linux-Kernel-Crypto-API"),
        ("uclient_http_set_ssl_ctx", "TLS"),
    ]:
        out = []
        cbomscan._match_sym(sym, 0, "defined", set(), out)
        assert out and out[0][0] == want, (sym, out)

def test_origin_noncrypto_kmods_and_libubox_md5():
    import sys as _sys
    _sys.path.insert(0, HERE)
    import cbomscan
    d = tempfile.mkdtemp()
    for fn in ("crc32c_generic.ko", "crypto_null.ko"):
        p = os.path.join(d, fn)
        open(p, "wb").write(b"\x7fELF" + b"\x00" * 32 + b"crypto_register_shash")
        bom = cbomscan.scan(p)
        assert [c for c in bom["components"] if c["type"] == "cryptographic-asset"] == []
    p_bytes = os.path.join(d, "a.bin")
    open(p_bytes, "wb").write(bytes.fromhex("06092a864886f70d010101"))
    b = cbomscan.scan(p_bytes)
    assert cbomscan._prop(b["components"][0], "cbomscan:origin") == "enthält"
    orig_needed = cbomscan.elf_needed
    orig_syms = cbomscan.elf_symbols
    try:
        cbomscan.elf_needed = lambda _p: [("libssl.so.3", 0)]
        cbomscan.elf_symbols = lambda _p: []
        p_use = os.path.join(d, "use.elf")
        open(p_use, "wb").write(b"\x7fELF\x00\x00\x00\x00libssl.so.3")
        b_use = cbomscan.scan(p_use)
        tls = [c for c in b_use["components"] if c["name"] == "TLS"][0]
        assert cbomscan._prop(tls, "cbomscan:origin") == "nutzt"
        cbomscan.elf_needed = lambda _p: []
        cbomscan.elf_symbols = lambda _p: [("MD5", "MD5", "hash", False, 0, "md5_begin", "defined")]
        p_md5 = os.path.join(d, "libubox.so")
        open(p_md5, "wb").write(b"\x7fELF\x00\x00\x00\x00md5_begin")
        b_md5 = cbomscan.scan(p_md5)
        md5c = [c for c in b_md5["components"] if c["name"] == "MD5"][0]
        assert cbomscan._prop(md5c, "cbomscan:note") == "Prüfsumme, nicht sicherheitsrelevant genutzt"
    finally:
        cbomscan.elf_needed = orig_needed
        cbomscan.elf_symbols = orig_syms
