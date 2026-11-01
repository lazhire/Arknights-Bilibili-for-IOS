from pathlib import Path
import json,unittest
from arkpatch_decrypted import validate_input,apply_binary_ranges,PatchError
ROOT=Path(__file__).resolve().parent

class FlexibleInputTests(unittest.TestCase):
    def setUp(self):
        self.m=json.loads((ROOT/'kit/manifest.json').read_bytes())
        self.s={k:self.m[k] for k in ('bundle_id','version','build','app_root')}
        self.s.update(encrypted=False,binaries={n:[dict(cpu=0x100000c,uuid=e['uuid'],cryptids=[0],sha256='different')] for n,e in self.m['host_binaries'].items()})
    def test_no_input_or_executable_hash_required(self):
        validate_input(self.s,self.m)
        self.s['ipa_sha256']='different';validate_input(self.s,self.m)
    def test_encrypted_rejected(self):
        self.s['encrypted']=True
        with self.assertRaisesRegex(PatchError,'ENCRYPTED_INPUT'):validate_input(self.s,self.m)
    def test_unsupported_version_rejected(self):
        self.s['version']='9.0.0'
        with self.assertRaisesRegex(PatchError,'UNSUPPORTED_LAYOUT'):validate_input(self.s,self.m)
    def test_wrong_uuid_rejected(self):
        next(iter(self.s['binaries'].values()))[0]['uuid']='different'
        with self.assertRaisesRegex(PatchError,'UUID'):validate_input(self.s,self.m)
    def test_missing_binary_rejected(self):
        self.s['binaries'].pop(next(iter(self.s['binaries'])))
        with self.assertRaises(PatchError):validate_input(self.s,self.m)
    def test_patch_preserves_unrelated_bytes(self):
        spec={'ranges':[dict(offset=1,before='42',after='58')]}
        self.assertEqual(apply_binary_ranges(b'ABC changed signature',spec),b'AXC changed signature')
    def test_wrong_preimage_rejected(self):
        with self.assertRaisesRegex(PatchError,'preimage'):
            apply_binary_ranges(b'AXC',{'ranges':[dict(offset=1,before='42',after='58')]})
    def test_out_of_bounds_rejected(self):
        with self.assertRaises(PatchError):
            apply_binary_ranges(b'ABC',{'ranges':[dict(offset=30,before='42',after='58')]})

if __name__=='__main__':unittest.main()
