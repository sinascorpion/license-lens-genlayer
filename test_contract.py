import importlib.util
import json
import pathlib
import sys
import types
import unittest

class Map(dict):
    @classmethod
    def __class_getitem__(cls, item): return cls
class Public:
    write = staticmethod(lambda f: f)
    view = staticmethod(lambda f: f)
class FakeGL:
    Contract = object
    public = Public()
    message = types.SimpleNamespace(sender_address='owner')
    UserError = ValueError
    nondet = types.SimpleNamespace(web=types.SimpleNamespace())
    eq_principle = types.SimpleNamespace(strict_eq=lambda fn: fn())

mod = types.ModuleType('genlayer')
mod.gl = FakeGL
mod.TreeMap = Map
mod.Address = str
mod.u64 = int
sys.modules['genlayer'] = mod
spec = importlib.util.spec_from_file_location('license_lens', pathlib.Path(__file__).with_name('contract.py'))
code = importlib.util.module_from_spec(spec)
spec.loader.exec_module(code)

class Tests(unittest.TestCase):
    def setUp(self):
        FakeGL.message.sender_address = 'owner'
        self.app = code.LicenseLens()
        self.app.policies = Map()
        self.app.audits = Map()
        self.app.create_policy('default', '["MIT", "Apache-2.0"]', '["GPL-3.0-only"]')
        FakeGL.nondet.web.request = lambda url, method: types.SimpleNamespace(status=200, body=json.dumps({'name':'lodash', 'version':'4.17.21', 'license':'MIT', 'dist':{'integrity':'sha512-example'}}).encode())
    def test_three_valued_expressions_and_precedence(self):
        a=['MIT']; d=['GPL-3.0-only']
        for expr, expected in [('MIT','ALLOW'),('GPL-3.0-only','DENY'),('MIT AND Zlib','UNKNOWN'),('GPL-3.0-only AND Zlib','DENY'),('MIT OR Zlib','ALLOW'),('GPL-3.0-only OR Zlib','UNKNOWN'),('(MIT OR GPL-3.0-only) AND MIT','ALLOW'),('MIT OR GPL-3.0-only AND Zlib','ALLOW'),('MIT WITH X','UNKNOWN'),('MIT OR','UNKNOWN'),('MIT; GPL-3.0-only','UNKNOWN')]:
            with self.subTest(expr=expr): self.assertEqual(code.license_verdict(expr,a,d), expected)
    def test_valid_audit_records_exact_identity_policy_and_integrity(self):
        self.assertEqual(self.app.audit_packages(1,'[{"name":"lodash","version":"4.17.21"}]'),1)
        audit=json.loads(self.app.get_audit(1))
        self.assertEqual((audit['policy_id'],audit['requester'],audit['overall']),(1,'owner','ALLOW'))
        self.assertEqual(audit['packages'][0]['integrity'],'sha512-example')
    def test_mismatch_or_outage_does_not_commit(self):
        for status, data in [(404,{}),(200,{'name':'evil','version':'4.17.21'})]:
            FakeGL.nondet.web.request=lambda *a,**kw: types.SimpleNamespace(status=status,body=json.dumps(data).encode())
            with self.assertRaises(ValueError): self.app.audit_packages(1,'[{"name":"lodash","version":"4.17.21"}]')
            self.assertEqual(self.app.audit_count,0)
    def test_invalid_inputs_and_policy_authority(self):
        FakeGL.message.sender_address='other'
        with self.assertRaises(AssertionError): self.app.create_policy('bad','["MIT"]','[]')
        for items in ['[]','[{"name":"lodash","version":"latest"}]','[{"name":"lodash","version":"4.17.21"},{"name":"lodash","version":"4.17.21"}]']:
            with self.assertRaises(AssertionError): self.app.audit_packages(1,items)
        with self.assertRaises(AssertionError): self.app.audit_packages(99,'[{"name":"lodash","version":"4.17.21"}]')
    def test_missing_license_is_unknown(self):
        FakeGL.nondet.web.request=lambda *a,**kw: types.SimpleNamespace(status=200,body=b'{"name":"lodash","version":"4.17.21"}')
        self.app.audit_packages(1,'[{"name":"lodash","version":"4.17.21"}]')
        self.assertEqual(json.loads(self.app.get_audit(1))['overall'],'UNKNOWN')

if __name__ == '__main__': unittest.main()
