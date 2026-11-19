#!/usr/bin/env python3
"""Summarize STARK run JSONL and render graphs without inventing any data.

Blank STARK metrics mean no verified proof run was available. The SHA256 chart
uses independently instrumented signature verifier observations, not estimates.
"""
import argparse
import csv
import json
from pathlib import Path
from statistics import median
import math

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

SIZES=[1,2,3,4,8,16,32,64,128]
METRICS=[
 ('stark_prove_seconds','Prove (s)'),
 ('stark_verify_seconds','Verify (ms)'),
 ('stark_proof_bytes','Proof (bytes)'),
 ('guest_execute_seconds','Guest execute (s)'),
 ('app_prove_seconds','App prove (s)'),
 ('app_verify_seconds','App verify (ms)'),
 ('app_proof_bytes','App proof (bytes)'),
 ('peak_ram_bytes','Peak RAM (bytes)'),
 ('vm_cycles','VM cycles'),
 ('sha2_accelerated_ops','SHA2 accelerated ops'),
 ('continuation_segments','Continuation segments'),
 ('air_trace_rows','AIR trace rows'),
]

def percentile_95(v):
    s=sorted(v)
    return s[min(len(s)-1,max(0,math.ceil(0.95*len(s))-1))]

def load_jsonl(path):
    if not path.exists():return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

def stats(values):
    if not values:return {'median':None,'min':None,'max':None,'p95':None,'samples':0}
    return {'median':median(values),'min':min(values),'max':max(values),
            'p95':percentile_95(values) if len(values)>=5 else None,'samples':len(values)}

def plot(path,title,xlabel,ylabel,points,unit=''):
    fig,ax=plt.subplots(figsize=(9.5,5.4))
    if points:
        xx,yy=zip(*points)
        ax.plot(xx,yy,'o-',linewidth=2)
        ax.grid(True,alpha=0.25)
        ax.set_xticks(SIZES)
        ax.set_xscale('log',base=2)
        ax.set_xticklabels([str(v) for v in SIZES])
    else:
        ax.text(0.5,0.5,'NOT MEASURED\nRun the OpenVM STARK benchmark first',
                transform=ax.transAxes,ha='center',va='center',fontsize=15,color='gray')
        ax.set_xlim(0,1);ax.set_ylim(0,1)
    ax.set_title(title)
    ax.set_xlabel(xlabel);ax.set_ylabel(ylabel+unit)
    fig.tight_layout();fig.savefig(path,dpi=160);plt.close(fig)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--out',type=Path,default=Path('results'))
    args=parser.parse_args()
    out=args.out;out.mkdir(parents=True,exist_ok=True)
    runs=load_jsonl(out/'runs.jsonl')
    good=[r for r in runs if r.get('status')=='ok' and not r.get('warmup')]
    crypto=list(csv.DictReader((out/'crypto_batch.csv').open()))
    by_n={int(r['n']):r for r in crypto}
    summary=[]
    detail={}
    for n in SIZES:
        valid=[r for r in good if r['n']==n]
        failed=[r for r in runs if r['n']==n and r.get('status')!='ok' and not r.get('warmup')]
        d={k:stats([float(r[k]) for r in valid if r.get(k) is not None]) for k,_ in METRICS}
        detail[str(n)]={'metrics':d,'failed_runs':failed,'success_runs':len(valid)}
        row={'N':n,'Status':'verified STARK proof' if any(r.get('stark_proof_bytes') for r in valid) else 'STARK not measured',
             'Successful runs':len(valid),'Failed runs':len(failed),
             'SHA-256 compressions':by_n[n]['sha256_compressions'],
             'SHA-256 calls':by_n[n]['sha256_calls'],
             'Commit SHA-256 compressions':by_n[n]['commit_sha256_compressions'],
             'Batch bytes':by_n[n]['batch_bytes'],
             'Batch commitment':by_n[n]['batch_commitment']}
        for key,label in METRICS:
            obj=d[key]
            factor=1000 if label.endswith('(ms)') else 1
            row[label]=obj['median']*factor if obj['median'] is not None else ''
            row[label+' min']=obj['min']*factor if obj['min'] is not None else ''
            row[label+' max']=obj['max']*factor if obj['max'] is not None else ''
            row[label+' p95']=obj['p95']*factor if obj['p95'] is not None else ''
        p=d['stark_prove_seconds']['median']; b=d['stark_proof_bytes']['median']
        row['Amortized prove (s/sig)']=p/n if p is not None else ''
        row['Signatures/s']=n/p if p else ''
        row['Proof bytes/signature']=b/n if b is not None else ''
        summary.append(row)
    with (out/'summary.csv').open('w',newline='') as fp:
        writer=csv.DictWriter(fp,summary[0].keys());writer.writeheader();writer.writerows(summary)
    (out/'statistics.json').write_text(json.dumps({'stark_has_been_run':bool(good),
         'benchmark_note':'SHA2 from independent FIPS205 Python counters; no estimated STARK measurements.',
         'details':detail},indent=2)+'\n')
    def pts(key,mod=lambda v:v):
        return [(n,mod(detail[str(n)]['metrics'][key]['median'])) for n in SIZES
                if detail[str(n)]['metrics'][key]['median'] is not None]
    plot(out/'01_proving_time.png','Aggregated STARK proving time','Number of signatures','Seconds',pts('stark_prove_seconds'))
    plot(out/'02_proof_size.png','Final aggregated STARK proof size','Number of signatures','Bytes',pts('stark_proof_bytes'))
    plot(out/'03_verification_time.png','Aggregated STARK verification time','Number of signatures','Milliseconds',pts('stark_verify_seconds',lambda v:v*1000))
    plot(out/'04_sha256_compressions.png','Measured SHA-256 compression blocks (signature verification)','Number of signatures','Compression blocks',[(n,int(by_n[n]['sha256_compressions'])) for n in SIZES])
    plot(out/'05_vm_cycles.png','OpenVM guest execution cycles','Number of signatures','VM cycles',pts('vm_cycles'))
    plot(out/'06_amortized_proving.png','Amortized aggregated STARK proving time','Number of signatures','Seconds per signature',[(n,detail[str(n)]['metrics']['stark_prove_seconds']['median']/n) for n in SIZES if detail[str(n)]['metrics']['stark_prove_seconds']['median'] is not None])
    print('Created summary, statistics, and six graphs. Verified STARK runs:',len(good))

if __name__=='__main__':main()
