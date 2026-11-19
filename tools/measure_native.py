#!/usr/bin/env python3
"""OpenSSL EVP baseline (CPU) with no per-signature process startup."""
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from protocol import fixture_bytes,load

ROOT=Path(__file__).resolve().parent.parent

def main():
    target=ROOT/'results'/'openssl_native.jsonl'
    target.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='slh-bench-') as t:
        t=Path(t)
        binary=t/'bench'
        flags=subprocess.check_output(['pkg-config','--cflags','--libs','openssl'],text=True).split()
        subprocess.run(['cc','-O3','-Wall','-Wextra','-o',str(binary),str(ROOT/'tools'/'openssl_bench.c'),*flags],check=True)
        records=load(str(ROOT/'fixtures'/'fixtures.json'))
        with target.open('w') as results:
            for n in (1,2,3,4,8,16,32,64,128):
                for i in range(5):
                    message,key,signature=fixture_bytes(records[(n+i)%len(records)])
                    for label,b in [('msg',message),('pk',key),('sig',signature)]:
                        (t/label).write_bytes(b)
                    res=subprocess.check_output([str(binary),str(t/'pk'),str(t/'msg'),str(t/'sig'),'1000'],text=True)
                    obj=json.loads(res)
                    obj.update({'n':n,'run':i,'host':platform.platform(),
                                'native_experiments':'1000 in-process OpenSSL verifications, representative fixture'})
                    results.write(json.dumps(obj)+'\n')
                print('OpenSSL baseline',n,'(5 x 1000 native verifies)',flush=True)
    print('Wrote',target)

if __name__=='__main__':main()
