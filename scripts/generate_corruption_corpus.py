"""Independent REGF fixture builder. Generates data and expectations; never invokes RegIns.

Run once to freeze tests/corpus. A subsequent recovery run consumes manifest.json.
Existing corpora are never overwritten. No user hive data is read.
"""
import base64
import hashlib
import json
import pathlib
import struct
import sys

destination = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "tests/corpus")
destination.mkdir(parents=True, exist_ok=True)
if (destination / "manifest.json").exists():
    raise SystemExit("Corpus already frozen; select a new directory to generate another version.")

def u32(b, p, n): struct.pack_into("<I", b, p, n & 0xffffffff)
def u16(b, p, n): struct.pack_into("<H", b, p, n)
def get32(b, p): return struct.unpack_from("<I", b, p)[0]
def checksum(b):
    n = 0
    for p in range(0, 508, 4): n ^= get32(b, p)
    u32(b, 508, 1 if n == 0 else 0xfffffffe if n == 0xffffffff else n)

data = bytearray(12288)
data[:4] = b"regf"
for p,n in [(4,1),(8,1),(20,1),(24,5),(32,1),(40,8192),(44,1)]: u32(data,p,n)
data[4096:4100] = b"hbin"; u32(data,4104,8192)
cursor = 4128
locations = {}

def cell(label, payload):
    global cursor
    n = (len(payload)+11)&~7
    p = cursor; cursor += n
    if cursor + 8 > len(data): raise RuntimeError("Fixture bin overflow")
    u32(data,p,-n); data[p+4:p+4+len(payload)] = payload
    locations[label] = p
    return p-4096

def nk(label,name,parent=0xffffffff,root=False):
    b = bytearray(76 + len(name)*2); b[:2]=b"nk"; u16(b,2,12 if root else 0)
    struct.pack_into("<q",b,4,132000000000000000)
    for p in [16,28,32,40,44,48]: u32(b,p,0xffffffff)
    u32(b,16,parent); u16(b,72,len(name)*2); b[76:]=name.encode("utf-16le")
    return cell(label,b)

root = nk("root","ROOT",root=True)
alpha = nk("alpha","Alpha",root)
beta = nk("beta","Beta",root)
leaf = nk("leaf","Leaf",alpha)

def li(label,children):
    b=bytearray(4+len(children)*4);b[:2]=b"li";u16(b,2,len(children))
    for i,c in enumerate(children):u32(b,4+i*4,c)
    return cell(label,b)

for label,children in [("root",[alpha,beta]),("alpha",[leaf])]:
    index=li(label+"-index",children);p=locations[label]+4;u32(data,p+20,len(children));u32(data,p+28,index)

security=bytearray(40);security[:2]=b"sk";u32(security,12,4);u32(security,16,20);security[20]=1;u16(security,22,0x8004)
sk=cell("security",security);u32(data,4096+sk+8,sk);u32(data,4096+sk+12,sk)
for label in ["root","alpha","beta","leaf"]:u32(data,locations[label]+4+44,sk)

expected_values={}
def value(key,label,name,payload,kind=3,inline=False):
    b=bytearray(20+len(name)*2);b[:2]=b"vk";u16(b,2,len(name)*2);u32(b,4,len(payload)|(0x80000000 if inline else 0));u32(b,12,kind);b[20:]=name.encode("utf-16le")
    if inline:b[8:8+len(payload)]=payload
    else:u32(b,8,cell(label+"-data",payload))
    ref=cell(label,b);listing=cell(label+"-list",struct.pack("<I",ref));p=locations[key]+4;u32(data,p+36,1);u32(data,p+40,listing)
    expected_values[label]={"key":key,"name":name,"type":kind,"hex":payload.hex()}

value("root","version","Version",b"\x01\x02\x03\x04",4,True)
value("alpha","text","Greeting","hello-registry\0".encode("utf-16le"),1)
value("beta","binary","Bytes",bytes(range(128)))
value("leaf","empty","",b"",0,True)
u32(data,36,root);u32(data,cursor,len(data)-cursor);checksum(data)
clean=bytes(data)

cases=[]
def emit(name,b,keys=None,values=None,loss=None,holes=None,scan_offset=4096,backup=False,extra=None):
    folder=destination/name;folder.mkdir()
    path=folder/"SYSTEM";path.write_bytes(b)
    case={"name":name,"file":str(path.relative_to(destination)),"sha256":hashlib.sha256(b).hexdigest(),"expected_keys":keys if keys is not None else ["ROOT","Alpha","Beta","Leaf"],"expected_values":values if values is not None else list(expected_values),"known_loss":loss or [],"holes":holes or [],"bins_offset":scan_offset,"backup_recovery":backup}
    if backup:
        (folder/"RegBack").mkdir();(folder/"RegBack"/"SYSTEM").write_bytes(clean)
        case["backup_sha256"]=hashlib.sha256(clean).hexdigest()
    if extra:case.update(extra)
    cases.append(case)

emit("00-clean",clean)
b=bytearray(clean);b[:4096]=bytes(4096);emit("01-zero-base",b)
b=bytearray(clean);b[4096:4128]=bytes(32);emit("02-zero-bin-header",b)
b=bytearray(clean);b[:4128]=bytes(4128);emit("03-zero-base-and-bin",b)
b=bytearray(clean);u32(b,36,0x7ffffff0);checksum(b);emit("04-bogus-root-reference",b)
for i,size in enumerate([0,0x80000000,7,0x7fffffff]):
    b=bytearray(clean);u32(b,locations["alpha"],size);emit(f"05-{i}-broken-key-cell-size",b)
b=bytearray(clean);u32(b,locations["beta"]+4+16,0x12345678);emit("06-broken-parent-index-survives",b,extra={"expected_parent":{"Beta":"ROOT"}})
b=bytearray(clean);b[locations["root-index"]+4:locations["root-index"]+8]=bytes(4);emit("07-erased-index-signature",b)
b=bytearray(clean);b[locations["beta"]+4:locations["beta"]+6]=b"??";emit("08-erased-key-signature",b)
b=bytearray(clean);p=locations["beta"];n=abs(struct.unpack_from("<i",b,p)[0]);moved=bytes(b[p:p+n]);b[p:p+n]=bytes(n);b.extend(bytes(113));b.extend(moved);emit("09-moved-key-record",b)
b=bytearray(clean);p=locations["text"];n=abs(struct.unpack_from("<i",b,p)[0]);moved=bytes(b[p:p+n]);b[p:p+n]=bytes(n);b.extend(bytes(53));b.extend(moved);emit("10-moved-value-record",b,values=["version","binary","empty"],loss=["Value ownership reference erased; Greeting must survive as unowned evidence."],extra={"expected_unowned":["Greeting"]})
b=bytearray(clean);p=locations["binary-data"]+4;b[p+17:p+24]=bytes(7);emit("11-zero-payload-bytes",b,values=["version","text","empty"],loss=["Zeroes are readable bytes; there is no evidence these seven bytes were overwritten."],extra={"expected_binary_zero_run":[17,7]})
emit("12-unreadable-payload-hole",clean,values=["version","text","empty"],holes=[[locations["binary-data"]+4+17,7]],loss=["Seven payload bytes unavailable; preserve remaining extents."],extra={"expected_partial_value":"Bytes","expected_readable_bytes":121})
b=bytearray(clean);b=b[:locations["binary-data"]+4+40];emit("13-truncated-tail",b,values=["version","text"],loss=["Tail value records and their lists are absent."])
b=bytearray(clean);u32(b,locations["alpha"]+4+36,0xffffffff);emit("14-exploding-value-count",b)
b=bytearray(clean);u32(b,locations["root-index"]+8,root);emit("15-self-referencing-index",b)
b=bytearray(clean);u32(b,locations["beta"]+4+16,beta);emit("16-parent-cycle-index-survives",b,extra={"expected_parent":{"Beta":"ROOT"}})
emit("17-empty-with-regback",b"",backup=True)
emit("18-empty-without-backup",b"",keys=[],values=[],loss=["No bytes or alternate sources exist; no recovery is possible."])
emit("19-all-zero-without-backup",bytes(len(clean)),keys=[],values=[],loss=["All evidence destroyed; do not invent a tree."])
emit("20-all-zero-with-regback",bytes(len(clean)),backup=True)
b=b"arbitrary-image-prefix"+bytes(15)+clean;emit("21-misaligned-whole-hive",b,scan_offset=4096+37,extra={"expected_carved_hive":37})
b=bytearray(clean);b[locations["alpha"]+4+76:locations["alpha"]+4+76+10]=bytes(10);emit("22-erased-key-name",b,keys=["ROOT","Beta","Leaf"],values=["version","binary","empty"],loss=["Alpha name destroyed; its former values may remain unowned."])
b=bytearray(clean);b[locations["security"]+4:locations["security"]+44]=bytes(40);emit("23-destroyed-security",b,extra={"export_requires_security_replacement":True})
b=bytearray(clean);b[:4128]=bytes(4128);u32(b,locations["alpha"],0);u32(b,locations["beta"]+4+16,0xeeeeeeee);emit("24-combined-structural-damage",b)
emit("25-two-hives-separated",clean+bytes(513)+clean,extra={"carving_only":True,"expected_hive_offsets":[0,len(clean)+513]},keys=[],values=[])
manifest={"version":1,"generator":"independent Python struct builder; no RegIns imports or execution","clean_sha256":hashlib.sha256(clean).hexdigest(),"locations":locations,"values":expected_values,"cases":cases}
encoded=json.dumps(manifest,indent=2).encode();(destination/"manifest.json").write_bytes(encoded)
(destination/"manifest.sha256").write_text(hashlib.sha256(encoded).hexdigest()+"\n")
print(f"Frozen {len(cases)} cases; manifest SHA-256 {hashlib.sha256(encoded).hexdigest()}")
