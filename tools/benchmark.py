#!/usr/bin/env python3
"""One-command fixture generation -> native OpenVM STARK proving -> reports.
This command *requires* a working OpenVM v2.1.0 toolchain.
"""
import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--n',type=int,help='positive batch size; omit for standard 1..128 suite')
    parser.add_argument('--repeats',type=int,default=5)
    parser.add_argument('--warmup',type=int,default=1)
    parser.add_argument('--timeout',type=int,default=0,help='seconds for the harness as a whole; 0 disables')
    parser.add_argument('--mode',choices=('both','app','stark'),default='both')
    parser.add_argument('--fixtures',default='fixtures/fixtures.json')
    parser.add_argument('--out',default='results')
    args=parser.parse_args()
    if args.n is not None and args.n<=0:parser.error('--n must be positive')
    if args.repeats<=0 or args.warmup<0:parser.error('invalid repeat/warmup')
    fixture_path=ROOT/args.fixtures
    needed=max(args.n or 128,128)
    subprocess.run([sys.executable,str(ROOT/'tools/generate_fixtures.py'),
                    '--count',str(needed),'--output',str(fixture_path)],cwd=ROOT,check=True)
    cmd=['cargo','run','--release','-p','slh-harness','--',
         '--repeats',str(args.repeats),'--warmup',str(args.warmup),
         '--fixtures',str(fixture_path),'--out',str(ROOT/args.out),
         '--mode',args.mode]
    cmd+=['--n',str(args.n)] if args.n is not None else ['--all']
    (ROOT/args.out).mkdir(exist_ok=True,parents=True)
    error=None
    try:
        subprocess.run(cmd,cwd=ROOT,check=True,timeout=args.timeout or None)
    except subprocess.TimeoutExpired as ex:
        error=f'timeout: {ex}'
    except (subprocess.CalledProcessError,FileNotFoundError) as ex:
        error=f'harness failed: {ex}'
    if error:
        record={'timestamp_utc':datetime.now(timezone.utc).isoformat(),
                'n':args.n or 'all','mode':args.mode,'status':'timeout' if error.startswith('timeout') else 'failed',
                'error':error}
        with (ROOT/args.out/'driver_errors.jsonl').open('a') as f:f.write(json.dumps(record)+'\n')
        print(error,file=sys.stderr)
    subprocess.run([sys.executable,str(ROOT/'tools/report.py'),'--out',str(ROOT/args.out)],cwd=ROOT,check=True)
    return int(error is not None)

if __name__=='__main__':raise SystemExit(main())
