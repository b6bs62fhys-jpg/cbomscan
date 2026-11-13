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
