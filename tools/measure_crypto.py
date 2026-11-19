#!/usr/bin/env python3
"""Run the independent (non-guest) verifier across 128 fixed OpenSSL fixtures.
Cryptographic counts are *measured*, NOT estimated from the signature parameters.
STARK performance fields are never populated by this script.
"""
import csv
import json
import sys
from collections import Counter
from hashlib import sha256
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent))
from protocol import load,encode_batch,commitment,fixture_bytes
from reference_check import Verify

COUNTS=(
 'sha256_calls','sha256_compressions','mgf1_calls','mgf1_sha256_calls',
 'role_F','role_H','role_T_l','role_H_msg_inner','role_MGF1',
 'fors_leaves','fors_auth_nodes','wots_chains','wots_steps','xmss_auth_nodes','hypertree_layers')
SIZES=[1,2,3,4,8,16,32,64,128]

def main():
    root=Path(__file__).resolve().parent.parent
    out=root/'results';out.mkdir(exist_ok=True)
    fixtures=load(str(root/'fixtures/fixtures.json'))
    result=[]
    for i,f in enumerate(fixtures):
        m,pk,sig=fixture_bytes(f)
        v=Verify(pk[:16]);assert v.verify(m,sig,pk),f'bad fixture {i}'
        operations=dict(v.ops)
        assert operations['sha256_calls']==sum(operations.get('role_'+r,0) for r in ['F','H','T_l','H_msg_inner','MGF1'])
        result.append({'index':i,'valid':True,'message_sha256':sha256(m).hexdigest(),
                       'public_key':pk.hex(), **{k:operations.get(k,0) for k in COUNTS}})
    with (out/'crypto_per_signature.jsonl').open('w') as fp:
        for rec in result:fp.write(json.dumps(rec)+'\n')
    rows=[]
    for n in SIZES:
        c=Counter()
        for rec in result[:n]:
            c.update({k:rec.get(k,0) for k in COUNTS})
        batch=encode_batch(fixtures[:n])
        rows.append({'n':n,'batch_commitment':commitment(fixtures[:n]),
                     'commit_sha256_calls':1,'commit_sha256_compressions':(len(batch)+9+63)//64,
                     'batch_bytes':len(batch),**{k:c.get(k,0) for k in COUNTS},
                     'source':'measured Python FIPS205 verifier; independent OpenSSL test fixtures'})
    with (out/'crypto_batch.csv').open('w',newline='') as fp:
        wr=csv.DictWriter(fp,rows[0].keys());wr.writeheader();wr.writerows(rows)
    print('Validated',len(result),'independent signatures with FIPS205 reference implementation')
    for r in rows: print('N',r['n'],'SHA256',r['sha256_calls'],'compressions',r['sha256_compressions'],'batch',r['batch_bytes'])

if __name__=='__main__':main()
