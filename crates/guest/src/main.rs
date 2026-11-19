#![cfg_attr(not(feature = "std"), no_main)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
use alloc::vec::Vec;
// `Digest` is needed on the host (sha2 trait methods) but not on the zkVM target.
#[allow(unused_imports)]
use openvm_sha2::{Digest, Sha256};

openvm::entry!(main);

const MAGIC: &[u8; 9] = b"SLHBATCH\x01";

fn read_u32(input: &[u8], at: &mut usize) -> u32 {
    let end = at.checked_add(4).expect("offset overflow");
    let word: [u8; 4] = input.get(*at..end).expect("truncated u32").try_into().unwrap();
    *at = end;
    u32::from_le_bytes(word)
}

fn read_field<'a>(input: &'a [u8], at: &mut usize, expected: usize) -> &'a [u8] {
    let len = read_u32(input, at) as usize;
    assert_eq!(len, expected, "unexpected fixed-length field");
    let end = at.checked_add(len).expect("field offset overflow");
    let field = input.get(*at..end).expect("truncated field");
    *at = end;
    field
}

pub fn main() {
    // Canonical full input: MAGIC || u16le(algorithm ID length) || algorithm ID
    // || u32le(count) || for each: u32le(msglen)||msg||u32le(pklen)||pk||u32le(siglen)||sig
    let batch: Vec<u8> = openvm::io::read();
    assert!(batch.starts_with(MAGIC), "invalid batch magic");
    let mut pos = MAGIC.len();
    let alg_end = pos.checked_add(2).expect("overflow");
    let alg_len = u16::from_le_bytes(batch.get(pos..alg_end).expect("truncated algorithm ID length").try_into().unwrap()) as usize;
    pos = alg_end;
    let id_end = pos.checked_add(alg_len).expect("overflow");
    assert_eq!(batch.get(pos..id_end).expect("truncated algorithm ID"), slh_core::ALGORITHM);
    pos = id_end;
    let count = read_u32(&batch, &mut pos);
    assert!(count > 0, "empty batch");

    for _ in 0..count {
        let msg_len = read_u32(&batch, &mut pos) as usize;
        assert!(msg_len <= 1024 * 1024, "message too large");
        let msg_end = pos.checked_add(msg_len).expect("message offset overflow");
        let msg = batch.get(pos..msg_end).expect("truncated message");
        pos = msg_end;
        let pk = read_field(&batch, &mut pos, slh_core::PUBLIC_KEY_SIZE);
        let sig = read_field(&batch, &mut pos, slh_core::SIGNATURE_SIZE);
        assert!(slh_core::verify(msg, sig, pk), "invalid signature");
    }
    assert_eq!(pos, batch.len(), "trailing bytes");

    // The commitment is computed by the guest, not supplied by the prover.
    // No proof succeeds without verifying *all* signatures.
    let mut hasher = Sha256::new();
    hasher.update(&batch);
    let digest: [u8; 32] = hasher.finalize().into();
    openvm::io::reveal_bytes32(digest);
    openvm::io::reveal_u32(count, 8); // word 8 = bytes 32..36, little-endian N
}
