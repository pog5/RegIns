"""Independent python-registry acceptance oracle; prints hashes/counts, not contents."""
import hashlib
import json
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path("artifacts/python-oracle")))
from Registry import Registry

results=[]
for filename in sys.argv[2:]:
    try:
        hive=Registry.Registry(filename)
        pending=[hive.root()]; keys=values=0
        logical=hashlib.sha256(); metadata=hashlib.sha256()
        def add(digest,blob): digest.update(struct.pack("<Q",len(blob)));digest.update(blob)
        while pending:
            key=pending.pop();keys+=1
            pending.extend(reversed(sorted(key.subkeys(),key=lambda k:k.name().upper())))
            path=key.path().encode("utf-8","surrogatepass")
            add(logical,path); add(metadata,path)
            nk=key._nkrecord; sk=nk.sk_record()
            descriptor=sk._buf[sk.offset()+20:sk.offset()+20+sk.unpack_dword(16)]
            add(metadata,descriptor);add(metadata,struct.pack("<Q",nk.unpack_qword(4)))
            add(metadata,nk.classname().encode("utf-16le","surrogatepass"))
            for value in sorted(key.values(),key=lambda v:v.name().upper()):
                values+=1;add(logical,value.name().encode("utf-8","surrogatepass"));add(logical,struct.pack("<I",value.value_type()));add(logical,value.raw_data())
        results.append(dict(file=filename,parsed=True,keys=keys,values=values,logical_sha256=logical.hexdigest(),security_class_timestamp_sha256=metadata.hexdigest()))
    except Exception as error: results.append(dict(file=filename,parsed=False,error=str(error)))
text=json.dumps(results,indent=2);pathlib.Path(sys.argv[1]).write_text(text);print(text)
