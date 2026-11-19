#!/usr/bin/env python3
"""Generate stable, independent OpenSSL >=3.5 FIPS 205 pure SLH-DSA fixtures.

The fixtures contain public material only; secret keys live temporarily in a
private TemporaryDirectory, and are not included in fixture JSON/ZIP.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from datetime import datetime, timezone

ALGORITHM = 'SLH-DSA-SHA2-128s'

def cmd(*args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def make_one(index):
    with tempfile.TemporaryDirectory(prefix='slh-fips205-') as temp:
        p = Path(temp)
        key, msg, sig, pub = (p / name for name in ('key.pem', 'msg.bin', 'sig.bin', 'pub.der'))
        cmd('openssl', 'genpkey', '-algorithm', ALGORITHM, '-out', str(key))
        message = f'PostBunker proof of validity; fixture {index:06d}\n'.encode() + os.urandom(24)
        msg.write_bytes(message)
        cmd('openssl','pkeyutl','-sign','-inkey',str(key),'-in',str(msg),'-out',str(sig))
        cmd('openssl','pkey','-in',str(key),'-pubout','-outform','DER','-out',str(pub))
        # OpenSSL encodes this algorithm as an RFC 5280 SPKI. Verify shape;
        # raw public key is the last 32 bytes after the BIT STRING header.
        der = pub.read_bytes()
        assert len(der) == 50 and der[0] == 0x30 and der[-33] == 0
        signature = sig.read_bytes()
        assert len(signature) == 7856
        cmd('openssl','pkeyutl','-verify','-pubin','-inkey',str(pub),'-keyform','DER',
            '-sigfile',str(sig),'-in',str(msg))
        return {'index':index, 'message_hex':message.hex(),
                'public_key_hex':der[-32:].hex(), 'signature_hex':signature.hex()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--count',type=int,default=128)
    parser.add_argument('--output',type=Path,default=Path('fixtures/fixtures.json'))
    args = parser.parse_args()
    if args.count < 1: parser.error('count must be positive')
    args.output.parent.mkdir(parents=True,exist_ok=True)
    if args.output.exists():
        data=json.loads(args.output.read_text())
        assert data['algorithm'] == ALGORITHM
        records=data['records']
    else:
        records=[]
    for i in range(len(records),args.count):
        records.append(make_one(i))
        if (i+1) % 8 == 0:
            args.output.write_text(json.dumps({'algorithm':ALGORITHM,'mode':'pure; empty context','generator':'OpenSSL >=3.5 pkeyutl','records':records}, separators=(',',':'))+'\n')
            print(f'Checkpointed {i+1}/{args.count} independent signatures', flush=True)
    assert len({r['public_key_hex'] for r in records})==len(records)
    data={'algorithm':ALGORITHM,'mode':'pure; empty context','generator':'OpenSSL >=3.5 pkeyutl',
          'records':records}
    args.output.write_text(json.dumps(data,separators=(',',':'))+'\n')
    digest=hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(f'{len(records)} fixtures | SHA256 file={digest} | path={args.output}')

if __name__ == '__main__': main()
