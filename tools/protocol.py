"""Canonical batch format shared by Python tests and Rust guest/host.

SLHBATCH\x01 | u16le(algo_len) | algorithm id | u32le(count) |
repeat count times [u32le(msglen) | msg | u32le(pklen) | pk | u32le(siglen) | sig].
"""
from hashlib import sha256
from pathlib import Path
import json
import struct

MAGIC = b'SLHBATCH\x01'
ALG = b'SLH-DSA-SHA2-128s/FIPS205/pure/ctx0'

def u32(x): return struct.pack('<I',x)

def enc_field(x): return u32(len(x))+x

def fixture_bytes(rec):
    return (bytes.fromhex(rec['message_hex']),bytes.fromhex(rec['public_key_hex']),
            bytes.fromhex(rec['signature_hex']))

def encode_batch(records):
    if not records: raise ValueError('empty batch')
    if len(records) > 0xffffffff: raise ValueError('count overflow')
    out=bytearray(MAGIC)
    out+=struct.pack('<H',len(ALG))+ALG+u32(len(records))
    for rec in records:
        m,pk,sig=fixture_bytes(rec)
        if len(m)>1024*1024 or len(pk)!=32 or len(sig)!=7856: raise ValueError('invalid fixture')
        out+=enc_field(m)+enc_field(pk)+enc_field(sig)
    return bytes(out)

def decode_batch(b):
    from io import BytesIO
    fp=BytesIO(b)
    def read(n):
        v=fp.read(n)
        if len(v)!=n: raise ValueError('truncated batch')
        return v
    if read(len(MAGIC))!=MAGIC: raise ValueError('invalid header')
    length=struct.unpack('<H',read(2))[0]
    if read(length)!=ALG: raise ValueError('unexpected algorithm')
    n=struct.unpack('<I',read(4))[0]
    if n<=0: raise ValueError('empty batch')
    result=[]
    for _ in range(n):
        size=struct.unpack('<I',read(4))[0]
        if size>1024*1024: raise ValueError('message too large')
        msg=read(size)
        pklen=struct.unpack('<I',read(4))[0]
        if pklen!=32: raise ValueError('bad pk length')
        pk=read(pklen)
        siglen=struct.unpack('<I',read(4))[0]
        if siglen!=7856: raise ValueError('bad sig length')
        sig=read(siglen)
        result.append((msg,pk,sig))
    if fp.read(1):raise ValueError('trailing bytes')
    return result

def commitment(records): return sha256(encode_batch(records)).hexdigest()

def load(path='fixtures/fixtures.json'):
    data=json.loads(Path(path).read_text())
    if data['algorithm']!='SLH-DSA-SHA2-128s':raise ValueError('algorithm mismatch')
    return data['records']
