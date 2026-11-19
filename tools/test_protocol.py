#!/usr/bin/env python3
"""Independent cryptographic + encoding negative tests, using real OpenSSL fixtures."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from protocol import load,encode_batch,decode_batch,commitment,fixture_bytes
from reference_check import Verify

class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.f = load(str(Path(__file__).resolve().parent.parent/'fixtures/fixtures.json'))
    def valid(self,r):
        msg,pk,sig=fixture_bytes(r)
        return Verify(pk[:16]).verify(msg,sig,pk)
    def test_three_independent_valid_signatures(self):
        for f in self.f[:3]:self.assertTrue(self.valid(f))
        self.assertEqual(len({f['public_key_hex'] for f in self.f}),128)
    def test_modified_message_fails(self):
        msg,pk,sig=fixture_bytes(self.f[0]); m=bytearray(msg);m[0]^=1
        self.assertFalse(Verify(pk[:16]).verify(bytes(m),sig,pk))
    def test_modified_public_key_fails(self):
        msg,pk,sig=fixture_bytes(self.f[0]);k=bytearray(pk);k[0]^=1
        self.assertFalse(Verify(bytes(k[:16])).verify(msg,sig,bytes(k)))
    def test_modified_signature_fails(self):
        msg,pk,sig=fixture_bytes(self.f[0]);s=bytearray(sig);s[10]^=1
        self.assertFalse(Verify(pk[:16]).verify(msg,bytes(s),pk))
    def test_truncated_signature_fails(self):
        msg,pk,sig=fixture_bytes(self.f[0]);self.assertFalse(Verify(pk[:16]).verify(msg,sig[:-1],pk))
    def test_batch_format(self):
        for n in (1,2,3,8):
            encoded=encode_batch(self.f[:n]); self.assertEqual(len(decode_batch(encoded)),n)
            self.assertNotEqual(commitment(self.f[:n]),commitment(self.f[1:n+1]))
        self.assertNotEqual(commitment(self.f[:2]),commitment(self.f[1::-1]))
    def test_format_negatives(self):
        b=bytearray(encode_batch(self.f[:1])); b[0]^=1
        with self.assertRaises(ValueError):decode_batch(b)
        b=encode_batch(self.f[:1]);
        with self.assertRaises(ValueError):decode_batch(b[:-2])
        with self.assertRaises(ValueError):decode_batch(b+b'x')
    def test_invalid_member_batch(self):
        records=[dict(f) for f in self.f[:3]]
        bad=bytearray.fromhex(records[1]['signature_hex']);bad[300]^=0x40
        records[1]['signature_hex']=bad.hex()
        self.assertFalse(self.valid(records[1]))
        self.assertNotEqual(commitment(records),commitment(self.f[:3]))
    def test_expected_public_values(self):
        n=3;h=bytes.fromhex(commitment(self.f[:n]));expected=h+n.to_bytes(4,'little')
        self.assertEqual(len(expected),36)
        self.assertNotEqual(expected, h+(2).to_bytes(4,'little'))
        self.assertNotEqual(expected,bytes.fromhex(commitment(self.f[1:4]))+(3).to_bytes(4,'little'))

if __name__=='__main__':unittest.main(verbosity=2)
