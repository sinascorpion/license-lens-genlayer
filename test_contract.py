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
    def test_policy_lists_must_be_disjoint_and_nonempty(self):
        for allow,deny in [('[]','[]'),('["MIT"]','["MIT"]'),('["MIT","MIT"]','[]')]:
            with self.subTest(allow=allow, deny=deny):
                with self.assertRaises((AssertionError,ValueError)): self.app.create_policy('bad',allow,deny)
        self.assertEqual(self.app.policy_count,1)
    def test_immutable_policy_snapshots_and_unknown_ids(self):
        self.assertEqual(self.app.get_policy(2),'')
        self.assertEqual(self.app.get_audit(1),'')
        policy=json.loads(self.app.get_policy(1))
        self.assertEqual(policy['allow'],['Apache-2.0','MIT'])
        self.assertEqual(policy['deny'],['GPL-3.0-only'])
    def test_mixed_results_aggregate_deny_and_sort(self):
        def request(url, method):
            name=url.split('/')[-2]
            license='GPL-3.0-only' if name=='bad' else 'MIT'
            return types.SimpleNamespace(status=200, body=json.dumps({'name':name,'version':'1.0.0','license':license}).encode())
        FakeGL.nondet.web.request=request
        self.app.audit_packages(1,'[{"name":"good","version":"1.0.0"},{"name":"bad","version":"1.0.0"}]')
        data=json.loads(self.app.get_audit(1))
        self.assertEqual(data['overall'],'DENY')
        self.assertEqual([item['name'] for item in data['packages']],['bad','good'])
    def test_disagreement_prevents_recording(self):
        previous=FakeGL.eq_principle.strict_eq
        def compare(fn):
            first=fn()
            FakeGL.nondet.web.request=lambda *a,**kw: types.SimpleNamespace(status=200,body=b'{"name":"lodash","version":"4.17.21","license":"GPL-3.0-only"}')
            second=fn()
            if first != second: raise ValueError('validator disagreement')
            return first
        FakeGL.eq_principle.strict_eq=compare
        try:
            with self.assertRaises(ValueError): self.app.audit_packages(1,'[{"name":"lodash","version":"4.17.21"}]')
            self.assertEqual(self.app.audit_count,0)
        finally: FakeGL.eq_principle.strict_eq=previous

if __name__ == '__main__': unittest.main()
