#!/usr/bin/env python3
"""Independent Python diagnostic implementation of FIPS 205 SHA2-128s verification.
Not used by the OpenVM guest or proof; used for cross-validation during development.
"""
from hashlib import sha256
from collections import Counter
from pathlib import Path
import sys

N, K, A, D, HP, LEN, SIGLEN = 16, 14, 12, 7, 9, 35, 7856
class Address:
    def __init__(self): self.b=bytearray(22)
    def copy(self):
        x=Address(); x.b[:]=self.b; return x
    def layer(self,x): self.b[0]=x
    def tree(self,x): self.b[1:9]=x.to_bytes(8,'big')
    def typ(self,x): self.b[9]=x; self.b[10:]=bytes(12)
    def keypair(self,x): self.b[10:14]=x.to_bytes(4,'big')
    def height(self,x): self.b[14:18]=x.to_bytes(4,'big')
    def index(self,x): self.b[18:22]=x.to_bytes(4,'big')
    def chain(self,x): self.height(x)
    def hashaddr(self,x): self.index(x)

class Verify:
    def __init__(self, seed): self.seed=seed; self.ops=Counter()
    def hash(self,data,role):
        self.ops['sha256_calls']+=1
        self.ops['sha256_compressions']+=(len(data)+9+63)//64
        self.ops['role_'+role]+=1
        return sha256(data).digest()
    def thash(self,adrs,m,role): return self.hash(self.seed+b'\0'*48+adrs.b+m,role)[:16]
    def f(self,adrs,m): return self.thash(adrs,m,'F')
    def h(self,adrs,m): return self.thash(adrs,m,'H')
    def t(self,adrs,m): return self.thash(adrs,m,'T_l')
    def hmsg(self,r,root,msg):
        self.ops['H_msg']+=1
        dg=self.hash(r+self.seed+root+b'\0\0'+msg,'H_msg_inner')
        s=r+self.seed+dg
        self.ops['mgf1_calls']+=1
        out=b''
        for idx in range(1):
            self.ops['mgf1_sha256_calls']+=1
            out+=self.hash(s+idx.to_bytes(4,'big'),'MGF1')
        return out[:30]
    @staticmethod
    def base(data,b,n):
        v=int.from_bytes(data,'big'); bits=len(data)*8
        return [(v>>(bits-(i+1)*b))&((1<<b)-1) for i in range(n)]
    def fors(self,sig,md,ad):
        indices=self.base(md,A,K)
        roots=[]
        for i,x in enumerate(indices):
            chunk=sig[i*(A+1)*N:(i+1)*(A+1)*N]
            sk=chunk[:16]
            ad.height(0); ad.index(i*(1<<A)+x)
            node=self.f(ad,sk)
            self.ops['fors_leaves']+=1
            for j in range(A):
                ad.height(j+1)
                curr=int.from_bytes(ad.b[18:22],'big')
                sibling=chunk[16*(1+j):16*(2+j)]
                ad.index(curr//2)
                node=self.h(ad,node+sibling if (x>>j)&1==0 else sibling+node)
                self.ops['fors_auth_nodes']+=1
            roots.append(node)
        keypair=int.from_bytes(ad.b[10:14],'big')
        ad.typ(4)
        ad.keypair(keypair)
        return self.t(ad,b''.join(roots))
    def wots(self,sig,msg,ad):
        digits=self.base(msg,4,32)
        csum=sum(15-i for i in digits)<<4
        digits+=self.base(csum.to_bytes(2,'big'),4,3)
        nodes=[]
        for i,start in enumerate(digits):
            ad.chain(i)
            node=sig[i*16:(i+1)*16]
            self.ops['wots_chains']+=1
            for j in range(start,15):
                ad.hashaddr(j)
                node=self.f(ad,node)
                self.ops['wots_steps']+=1
            nodes.append(node)
        pkad=ad.copy(); pkad.typ(1)
        pkad.keypair(int.from_bytes(ad.b[10:14],'big'))
        return self.t(pkad,b''.join(nodes))
    def xmss(self,sig,msg,ad,idx):
        ad.typ(0); ad.keypair(idx)
        node=self.wots(sig[:LEN*16],msg,ad)
        ad.typ(2); ad.index(idx)
        for j in range(HP):
            ad.height(j+1)
            v=int.from_bytes(ad.b[18:22],'big')
            ad.index(v//2)
            sibling=sig[LEN*16+j*16:LEN*16+(j+1)*16]
            node=self.h(ad,node+sibling if (idx>>j)&1==0 else sibling+node)
            self.ops['xmss_auth_nodes']+=1
        return node
    def verify(self,msg,signature,pk):
        if len(signature)!=SIGLEN or len(pk)!=32: return False
        r=signature[:16]; seed=pk[:16]; root=pk[16:]
        if seed != self.seed: return False
        digest=self.hmsg(r,root,msg)
        md=digest[:21]
        idx_tree=int.from_bytes(digest[21:28],'big')&((1<<54)-1)
        idx_leaf=int.from_bytes(digest[28:30],'big')&((1<<9)-1)
        ad=Address(); ad.tree(idx_tree); ad.typ(3); ad.keypair(idx_leaf)
        fors_sig=signature[16:16+14*13*16]
        node=self.fors(fors_sig,md,ad)
        offset=16+14*13*16
        for layer in range(D):
            ad=Address(); ad.layer(layer); ad.tree(idx_tree)
            sub_sig=signature[offset:offset+(LEN+HP)*16]
            node=self.xmss(sub_sig,node,ad,idx_leaf)
            self.ops['hypertree_layers']+=1
            offset+=(LEN+HP)*16
            idx_leaf=idx_tree & 511; idx_tree>>=9
        return node==root

if __name__=='__main__':
    p=Path(sys.argv[1] if len(sys.argv)>1 else '/tmp/poc')
    msg=p.with_name(p.name+'-msg.bin').read_bytes()
    sig=p.with_name(p.name+'-sig.bin').read_bytes()
    der=p.with_name(p.name+'-pk.der').read_bytes()
    assert len(der)==50
    pk=der[-32:]
    v=Verify(pk[:16]); ok=v.verify(msg,sig,pk)
    print('VALID',ok); print(dict(v.ops))
    assert ok
