import json, hashlib, hmac, base64, struct, subprocess, sys, os, tempfile
v=json.load(open(sys.argv[1])); H=bytes.fromhex
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
ok=0
def eq(a,b,what):
    global ok
    if a!=b: print("MISMATCH",what,a,b); sys.exit(1)
    ok+=1
for k in v["keys"].values():
    spki=H(k["spkiDER"]); eq(spki[-65:].hex(),k["publicPoint"],"point in spki")
    fp=hashlib.sha256(spki).digest(); eq(fp.hex(),k["fingerprint"],"fp")
    n=int.from_bytes(fp[:10],"big"); a="0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    eq("".join(a[(n>>(75-5*i))&31] for i in range(16)),k["macID"],"macID")
mac,dev=H(v["keys"]["mac"]["fingerprint"]),H(v["keys"]["device"]["fingerprint"])
p=v["pairing"]; key=hashlib.pbkdf2_hmac("sha256",p["code"].encode(),b"sill-pair-v1"+mac,600000,32)
eq(key.hex(),p["typedPath"]["keyHex"],"pbkdf2"); eq(H(p["pbkdf2"]["saltHex"]),b"sill-pair-v1"+mac,"salt")
for path in ("typedPath","qrPath"):
    k=H(p[path]["keyHex"])
    eq(hmac.new(k,b"sill-pair-v1 device\0"+dev+mac,"sha256").hexdigest(),p[path]["deviceProofHex"],path+" D")
    eq(hmac.new(k,b"sill-pair-v1 mac\0"+mac+dev,"sha256").hexdigest(),p[path]["macProofHex"],path+" M")
eq(p["qrPath"]["keyHex"],p["qrPath"]["secretHex"],"qr key is secret")
t=p["recognitionTag"]; nonce=H(t["nonceHex"])
eq(b64u(nonce+hmac.new(H(t["recognitionKeyHex"]),b"sill-tag-v1"+nonce,"sha256").digest()[:6]),t["tag"],"tag")
interim=0
for d in p["code"]: interim=p["dammTable"][interim][int(d)]
eq(interim,0,"damm")
for m in v["framing"]["messages"]:
    if "payloadHex" not in m: continue
    w=H(m["wireHex"]); eq(w[0],m["kind"],"kind"); eq(struct.unpack(">d",w[1:9])[0],m["timestamp"],"ts")
    eq(w[9],1 if m["isKeyframe"] else 0,"kf"); eq(struct.unpack(">I",w[10:14])[0],len(H(m["payloadHex"])),"len"); eq(w[14:].hex(),m["payloadHex"],"payload")
# ECDSA kind 18 with openssl
s=v["macInfo"]["signed"]; d=tempfile.mkdtemp()
open(d+"/info","wb").write(base64.b64decode(s["info"])); open(d+"/sig","wb").write(base64.b64decode(s["sig"]))
open(d+"/pub.der","wb").write(H(v["keys"]["mac"]["spkiDER"]))
r=subprocess.run(["/usr/bin/openssl","dgst","-sha256","-verify",d+"/pub.der","-keyform","DER","-signature",d+"/sig",d+"/info"],capture_output=True,text=True)
eq("Verified OK" in r.stdout,True,"ecdsa "+r.stdout+r.stderr)
open(d+"/cert.der","wb").write(H(v["certificate"]["derHex"]))
r=subprocess.run(["/usr/bin/openssl","x509","-inform","DER","-in",d+"/cert.der","-pubkey","-noout"],capture_output=True,text=True)
pem=r.stdout; open(d+"/c.pem","w").write(pem)
r=subprocess.run(["/usr/bin/openssl","pkey","-pubin","-in",d+"/c.pem","-outform","DER"],capture_output=True)
eq(hashlib.sha256(r.stdout).hexdigest(),v["keys"]["mac"]["fingerprint"],"cert spki")
r=subprocess.run(["/usr/bin/openssl","verify","-check_ss_sig","-partial_chain","-CAfile",d+"/cert.der","-no-CApath",d+"/cert.der"],capture_output=True,text=True)
print("cross-check: %d checks passed"%ok)
