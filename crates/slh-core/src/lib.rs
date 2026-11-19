//! FIPS 205 (FINAL) pure SLH-DSA-SHA2-128s verification.
//! No signing, no EC cryptography. SHA256 is routed through OpenVM's accelerated
//! guest SHA2 extension when compiled for the zkvm target.
#![no_std]

// `Digest` is needed on the host (sha2 trait methods) but not on the zkVM target.
#[allow(unused_imports)]
use openvm_sha2::{Digest, Sha256};

pub const ALGORITHM: &[u8] = b"SLH-DSA-SHA2-128s/FIPS205/pure/ctx0";
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 7856;
pub const N: usize = 16;
const K: usize = 14;
const A: usize = 12;
const D: usize = 7;
const H_PRIME: usize = 9;
const WOTS_LEN: usize = 35;
const WOTS_SIG_BYTES: usize = WOTS_LEN * N;
const XMSS_SIG_BYTES: usize = (WOTS_LEN + H_PRIME) * N;
const FORS_SIG_BYTES: usize = K * (A + 1) * N;
const ZERO48: [u8; 48] = [0; 48];

/// Hash-operation counters are compiled out of the guest when the `instrument`
/// feature is disabled. Counters are collected from an independent native run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub sha256_calls: u64,
    pub sha256_compressions: u64,
    pub mgf1_calls: u64,
    pub mgf1_sha256_calls: u64,
    pub h_msg_inner: u64,
    pub f: u64,
    pub h: u64,
    pub t_l: u64,
    pub fors_leaves: u64,
    pub fors_auth_nodes: u64,
    pub wots_chains: u64,
    pub wots_steps: u64,
    pub xmss_auth_nodes: u64,
    pub hypertree_layers: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role { HMsg, Mgf1, F, H, Tl }

#[derive(Clone, Copy)]
struct Address { data: [u8; 22] }
impl Address {
    fn new() -> Self { Self { data: [0; 22] } }
    fn layer(&mut self, v: u8) { self.data[0] = v; }
    fn tree(&mut self, v: u64) { self.data[1..9].copy_from_slice(&v.to_be_bytes()); }
    fn kind(&mut self, v: u8) {
        self.data[9] = v;
        self.data[10..22].fill(0);
    }
    fn keypair(&mut self, v: u32) { self.data[10..14].copy_from_slice(&v.to_be_bytes()); }
    fn height(&mut self, v: u32) { self.data[14..18].copy_from_slice(&v.to_be_bytes()); }
    fn index(&mut self, v: u32) { self.data[18..22].copy_from_slice(&v.to_be_bytes()); }
    fn index_value(&self) -> u32 { u32::from_be_bytes(self.data[18..22].try_into().unwrap()) }
}

struct Verifier {
    seed: [u8; 16],
    counts: Counts,
}
impl Verifier {
    fn new(seed: &[u8]) -> Self { Self { seed: seed.try_into().unwrap(), counts: Counts::default() } }

    /// SHA256 with split data, avoiding temporary allocations. Count exact
    /// compression blocks including the SHA-256 Merkle-Damgard final padding.
    fn hash(&mut self, parts: &[&[u8]], role: Role) -> [u8; 32] {
        #[cfg(feature = "instrument")]
        {
            let len: u64 = parts.iter().map(|part| part.len() as u64).sum();
            self.counts.sha256_calls += 1;
            self.counts.sha256_compressions += (len + 9 + 63) / 64;
            match role {
                Role::HMsg => self.counts.h_msg_inner += 1,
                Role::Mgf1 => { self.counts.mgf1_sha256_calls += 1; },
                Role::F => self.counts.f += 1,
                Role::H => self.counts.h += 1,
                Role::Tl => self.counts.t_l += 1,
            }
        }
        #[cfg(not(feature = "instrument"))]
        let _ = role;
        let mut sha = Sha256::new();
        for part in parts { sha.update(part); }
        sha.finalize().into()
    }

    fn thash(&mut self, adrs: &Address, message: &[u8], role: Role) -> [u8; 16] {
        let seed = self.seed;
        let out = self.hash(&[&seed, &ZERO48, &adrs.data, message], role);
        out[..16].try_into().unwrap()
    }
    fn f(&mut self, a: &Address, x: &[u8]) -> [u8; 16] { self.thash(a,x,Role::F) }
    fn h(&mut self, a: &Address, x: &[u8]) -> [u8; 16] { self.thash(a,x,Role::H) }
    fn t_l(&mut self, a: &Address, x: &[u8]) -> [u8; 16] { self.thash(a,x,Role::Tl) }

    /// FIPS 205 11.2.1 H_msg: SHA256(R||seed||root||0x00||0x00||msg)
    /// then MGF1-SHA256(R||seed||inner, m=30), which takes exactly one digest.
    fn h_msg(&mut self, r: &[u8], root: &[u8], msg: &[u8]) -> [u8; 30] {
        let seed = self.seed;
        let inner = self.hash(&[r,&seed,root,&[0,0],msg],Role::HMsg);
        #[cfg(feature = "instrument")]
        { self.counts.mgf1_calls += 1; }
        let expanded = self.hash(&[r,&seed,&inner,&0u32.to_be_bytes()], Role::Mgf1);
        expanded[..30].try_into().unwrap()
    }

    fn fors(&mut self, sig: &[u8], md: &[u8], ad: &mut Address) -> [u8;16] {
        let mut roots = [0u8; K*N];
        for i in 0..K {
            let idx = base_n_at(md, A, i);
            let sk = &sig[i*(A+1)*N..(i*(A+1)+1)*N];
            ad.height(0);
            ad.index(((i << A) as u32) + idx);
            let mut node = self.f(ad, sk);
            #[cfg(feature = "instrument")]
            { self.counts.fors_leaves += 1; }
            for j in 0..A {
                ad.height((j + 1) as u32);
                let current = ad.index_value();
                ad.index(current / 2);
                let auth_pos = (i*(A+1)+1+j)*N;
                let auth = &sig[auth_pos..auth_pos+N];
                let mut pair = [0u8; 2*N];
                if ((idx >> j) & 1) == 0 {
                    pair[..N].copy_from_slice(&node);
                    pair[N..].copy_from_slice(auth);
                } else {
                    pair[..N].copy_from_slice(auth);
                    pair[N..].copy_from_slice(&node);
                }
                node = self.h(ad, &pair);
                #[cfg(feature = "instrument")]
                { self.counts.fors_auth_nodes += 1; }
            }
            roots[i*N..(i+1)*N].copy_from_slice(&node);
        }
        let keypair = u32::from_be_bytes(ad.data[10..14].try_into().unwrap());
        ad.kind(4); // FORS_ROOTS; type transition MUST clear following 12 bytes
        ad.keypair(keypair);
        self.t_l(ad,&roots)
    }

    fn wots(&mut self, sig: &[u8], msg: &[u8; N], ad: &mut Address) -> [u8; N] {
        let mut digits=[0u8; WOTS_LEN];
        let mut checksum=0u32;
        for (i, digit) in digits.iter_mut().take(32).enumerate() {
            *digit = base_n_at(msg,4,i) as u8;
            checksum += 15 - *digit as u32;
        }
        checksum <<= 4; // FIPS 205 Alg 8: LEN2=3 => pad checksum by 4 bits
        let check_be = (checksum as u16).to_be_bytes();
        for (i,digit) in digits.iter_mut().enumerate().skip(32) {
            *digit=base_n_at(&check_be, 4, i-32) as u8;
        }
        let mut tmp=[0u8; WOTS_SIG_BYTES];
        for (i, start) in digits.iter().enumerate() {
            ad.height(i as u32); // chain address
            let mut node: [u8; N] = sig[i*N..(i+1)*N].try_into().unwrap();
            #[cfg(feature = "instrument")]
            { self.counts.wots_chains += 1; }
            for j in *start as u32..15 {
                ad.index(j); // hash address
                node=self.f(ad,&node);
                #[cfg(feature = "instrument")]
                { self.counts.wots_steps += 1; }
            }
            tmp[i*N..(i+1)*N].copy_from_slice(&node);
        }
        let mut pk_ad=*ad;
        pk_ad.kind(1); // WOTS_PK
        // Type change clears keypair; reapply it from original address.
        pk_ad.keypair(u32::from_be_bytes(ad.data[10..14].try_into().unwrap()));
        self.t_l(&pk_ad,&tmp)
    }

    fn xmss(&mut self, sig: &[u8], msg: &[u8; N], ad: &mut Address, leaf: u32) -> [u8; N] {
        ad.kind(0); // WOTS_HASH
        ad.keypair(leaf);
        let mut node=self.wots(&sig[..WOTS_SIG_BYTES],msg,ad);
        ad.kind(2); // TREE
        ad.index(leaf);
        for j in 0..H_PRIME {
            ad.height((j+1) as u32);
            let index=ad.index_value();
            ad.index(index/2);
            let auth=&sig[WOTS_SIG_BYTES+j*N..WOTS_SIG_BYTES+(j+1)*N];
            let mut pair=[0u8; N*2];
            if ((leaf>>j)&1)==0 {
                pair[..N].copy_from_slice(&node);
                pair[N..].copy_from_slice(auth);
            } else {
                pair[..N].copy_from_slice(auth);
                pair[N..].copy_from_slice(&node);
            }
            node=self.h(ad,&pair);
            #[cfg(feature = "instrument")]
            { self.counts.xmss_auth_nodes += 1; }
        }
        node
    }

    fn verify(&mut self, msg: &[u8], sig: &[u8], pk: &[u8]) -> bool {
        if pk.len()!=PUBLIC_KEY_SIZE || sig.len()!=SIGNATURE_SIZE {return false;}
        let root=&pk[N..2*N];
        let digest=self.h_msg(&sig[..N],root,msg);
        let md=&digest[..21]; // ceil(K*A/8)
        let mut tree=u64::from_be_bytes([0,digest[21],digest[22],digest[23],digest[24],digest[25],digest[26],digest[27]]) & ((1u64<<54)-1);
        let mut leaf=u16::from_be_bytes([digest[28],digest[29]]) as u32 & 511;
        let mut addr=Address::new();
        addr.tree(tree);
        addr.kind(3); // FORS_TREE
        addr.keypair(leaf);
        let mut node=self.fors(&sig[N..N+FORS_SIG_BYTES],md,&mut addr);
        let mut pos=N+FORS_SIG_BYTES;
        for layer in 0..D {
            let mut ad=Address::new();
            ad.layer(layer as u8);
            ad.tree(tree);
            node=self.xmss(&sig[pos..pos+XMSS_SIG_BYTES],&node,&mut ad,leaf);
            pos+=XMSS_SIG_BYTES;
            #[cfg(feature = "instrument")]
            { self.counts.hypertree_layers += 1; }
            leaf=(tree & 511) as u32;
            tree >>= 9;
        }
        // Constant-time comparison to avoid accidental timing-based acceptance.
        let mut diff=0u8;
        for i in 0..N {diff |= node[i] ^ root[i];}
        diff==0 && pos==SIGNATURE_SIZE
    }
}

/// Extract the ith b-bit element from a byte string MSB-first (FIPS 205 Alg 4).
/// All calls have 0 < b <= 12, so no overflow or shift by 32.
fn base_n_at(data: &[u8], bits: usize, i: usize) -> u32 {
    let start=i*bits;
    let mut acc=0u32;
    for bit in start..start+bits {
        acc=(acc<<1) | (((data[bit/8]>>(7-(bit%8))) & 1) as u32);
    }
    acc
}

/// Pure SLH-DSA verification, empty context. Does not require heap allocation.
pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    if public_key.len()!=PUBLIC_KEY_SIZE || signature.len()!=SIGNATURE_SIZE {return false;}
    Verifier::new(&public_key[..N]).verify(message,signature,public_key)
}

/// Separate instrumented execution. Compile with `--features instrument` to
/// populate counters (otherwise all fields remain zero by construction).
pub fn verify_with_counts(message: &[u8], signature: &[u8], public_key: &[u8]) -> (bool, Counts) {
    if public_key.len()!=PUBLIC_KEY_SIZE || signature.len()!=SIGNATURE_SIZE { return (false,Counts::default()); }
    let mut v=Verifier::new(&public_key[..N]);
    let result=v.verify(message,signature,public_key);
    (result,v.counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sizes_match_fips205() {
        assert_eq!(N+FORS_SIG_BYTES+D*XMSS_SIG_BYTES,SIGNATURE_SIZE);
        assert_eq!(FORS_SIG_BYTES,2912);
        assert_eq!(XMSS_SIG_BYTES,704);
    }
    #[test]
    fn four_bit_wots_checksum() {
        let test=[0xffu8;16];
        assert_eq!(base_n_at(&test,4,0),15);
        assert_eq!(base_n_at(&test,4,31),15);
        let t=[0x12u8,0x34];
        assert_eq!(base_n_at(&t,4,2),3);
    }
    #[test]
    fn rejects_bad_lengths() {
        assert!(!verify(b"hi",&[0;SIGNATURE_SIZE-1],&[0;32]));
        assert!(!verify(b"hi",&[0;SIGNATURE_SIZE],&[0;31]));
    }
}
