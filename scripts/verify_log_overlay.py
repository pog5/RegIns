"""Acceptance oracle: apply integrity-checked HvLE pages using python-registry.
Never used by production code. Refuses existing output files.
"""
import pathlib
import struct
import sys

sys.path.insert(0,"artifacts/python-oracle")
from Registry.RegistryParse import HvLEBlock
primary=bytearray(pathlib.Path(sys.argv[1]).read_bytes())
log=pathlib.Path(sys.argv[2]).read_bytes()
entries=[]
for p in range(512,len(log)-40,512):
    if log[p:p+4]!=b"HvLE":continue
    h=HvLEBlock(log,p,None)
    size,flags,sequence,bins,count=struct.unpack_from("<IIIII",log,p+4)
    if p+size>len(log):continue
    if h.marvin32_hash(log[p+40:p+size])!=struct.unpack_from("<Q",log,p+24)[0]:continue
    if h.marvin32_hash(log[p:p+32])!=struct.unpack_from("<Q",log,p+32)[0]:continue
    cursor=p+40+count*8
    if len(primary)<4096+bins:primary.extend(bytes(4096+bins-len(primary)))
    for i in range(count):
        offset,length=struct.unpack_from("<II",log,p+40+i*8)
        if cursor+length>p+size or offset+length>bins:raise ValueError("Bad page reference")
        primary[4096+offset:4096+offset+length]=log[cursor:cursor+length];cursor+=length
    struct.pack_into("<II",primary,4,sequence,sequence);struct.pack_into("<I",primary,40,bins)
    entries.append(sequence)
checksum=0
for p in range(0,508,4):checksum^=struct.unpack_from("<I",primary,p)[0]
struct.pack_into("<I",primary,508,1 if checksum==0 else 0xfffffffe if checksum==0xffffffff else checksum)
with open(sys.argv[3],"xb") as f:f.write(primary)
print({"independently_applied_sequences":entries})
