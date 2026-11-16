# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
import json
import re
from urllib.parse import quote


def parse_list(raw):
    data = json.loads(raw)
    if not isinstance(data, list) or len(data) > 40:
        raise ValueError('Expected a list of at most 40 license identifiers')
    if any(not isinstance(x, str) or not re.fullmatch(r'[A-Za-z0-9.+-]{1,80}', x) for x in data):
        raise ValueError('Invalid license identifier')
    if len(set(data)) != len(data):
        raise ValueError('Duplicate license identifier')
    return sorted(data)


def license_verdict(expression, allow, deny):
    """Three-valued evaluator for the AND/OR SPDX subset; unsupported syntax fails closed."""
    if not isinstance(expression, str) or not 0 < len(expression) <= 256:
        return 'UNKNOWN'
    tokens = re.findall(r'\(|\)|[A-Za-z0-9.+-]+|\S', expression)
    if len(tokens) > 80:
        return 'UNKNOWN'
    pos = 0

    def term():
        nonlocal pos
        if pos >= len(tokens): raise ValueError('Missing operand')
        token = tokens[pos]
        pos += 1
        if token == '(':
            value = disjunction()
            if pos >= len(tokens) or tokens[pos] != ')': raise ValueError('Missing parenthesis')
            pos += 1
            return value
        if token in ('AND', 'OR', 'WITH', ')') or not re.fullmatch(r'[A-Za-z0-9.+-]{1,80}', token):
            raise ValueError('Unsupported expression')
        if token in allow: return 'ALLOW'
        if token in deny: return 'DENY'
        return 'UNKNOWN'

    def conjunction():
        nonlocal pos
        values = [term()]
        while pos < len(tokens) and tokens[pos] == 'AND':
            pos += 1
            values.append(term())
        return 'DENY' if 'DENY' in values else 'UNKNOWN' if 'UNKNOWN' in values else 'ALLOW'

    def disjunction():
        nonlocal pos
        values = [conjunction()]
        while pos < len(tokens) and tokens[pos] == 'OR':
            pos += 1
            values.append(conjunction())
        return 'ALLOW' if 'ALLOW' in values else 'UNKNOWN' if 'UNKNOWN' in values else 'DENY'
    try:
        answer = disjunction()
        return answer if pos == len(tokens) else 'UNKNOWN'
    except (ValueError, RecursionError):
        return 'UNKNOWN'


class LicenseLens(gl.Contract):
    owner: Address
    policy_count: u64
    audit_count: u64
    policies: TreeMap[str, str]
    audits: TreeMap[str, str]

    def __init__(self):
        self.owner = gl.message.sender_address
        self.policy_count = 0
        self.audit_count = 0

    @gl.public.write
    def create_policy(self, name: str, allow_json: str, deny_json: str) -> u64:
        assert gl.message.sender_address == self.owner, 'Only the owner may create policies'
        assert 0 < len(name.strip()) <= 80, 'Invalid policy name'
        allow, deny = parse_list(allow_json), parse_list(deny_json)
        assert len(allow) + len(deny) > 0, 'Policy is empty'
        assert not set(allow).intersection(deny), 'License cannot be both allowed and denied'
        self.policy_count += 1
        self.policies[str(self.policy_count)] = json.dumps({'id': int(self.policy_count), 'name': name.strip(), 'allow': allow, 'deny': deny}, sort_keys=True)
        return self.policy_count

    @gl.public.write
    def audit_packages(self, policy_id: u64, packages_json: str) -> u64:
        stored = self.policies.get(str(policy_id), '')
        assert stored, 'Unknown policy'
        policy = json.loads(stored)
        packages = json.loads(packages_json)
        assert isinstance(packages, list) and 1 <= len(packages) <= 8, 'Supply one to eight packages'
        normalized = []
        for item in packages:
            assert isinstance(item, dict) and set(item.keys()) == {'name', 'version'}, 'Expected name and version'
            name, version = item['name'], item['version']
            assert isinstance(name, str) and re.fullmatch(r'(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]{0,100}', name) and len(name) <= 150, 'Invalid npm package name'
            assert isinstance(version, str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?', version) and len(version) <= 80, 'Use an exact version'
            assert (name, version) not in normalized, 'Duplicate package/version'
            normalized.append((name, version))
        normalized.sort()

        def observe():
            results = []
            for name, version in normalized:
                url = 'https://registry.npmjs.org/' + quote(name, safe='') + '/' + quote(version, safe='')
                response = gl.nondet.web.request(url, method='GET')
                if response.status != 200 or response.body is None:
                    raise gl.UserError('npm registry unavailable or version not found')
                obj = json.loads(response.body.decode('utf-8'))
                if not isinstance(obj, dict) or obj.get('name') != name or obj.get('version') != version:
                    raise gl.UserError('npm metadata does not match requested package/version')
                license_value = obj.get('license')
                if not isinstance(license_value, str) or len(license_value) > 256:
                    license_value = ''
                dist = obj.get('dist')
                integrity = dist.get('integrity', '') if isinstance(dist, dict) else ''
                if not isinstance(integrity, str) or len(integrity) > 300:
                    integrity = ''
                results.append({'name': name, 'version': version, 'license': license_value, 'integrity': integrity, 'verdict': license_verdict(license_value, policy['allow'], policy['deny'])})
            return json.dumps(results, sort_keys=True, separators=(',', ':'))

        observations = json.loads(gl.eq_principle.strict_eq(observe))
        outcomes = [item['verdict'] for item in observations]
        overall = 'DENY' if 'DENY' in outcomes else 'UNKNOWN' if 'UNKNOWN' in outcomes else 'ALLOW'
        self.audit_count += 1
        self.audits[str(self.audit_count)] = json.dumps({'id': int(self.audit_count), 'policy_id': int(policy_id), 'requester': str(gl.message.sender_address), 'overall': overall, 'packages': observations}, sort_keys=True)
        return self.audit_count

    @gl.public.view
    def get_policy(self, policy_id: u64) -> str:
        return self.policies.get(str(policy_id), '')

    @gl.public.view
    def get_audit(self, audit_id: u64) -> str:
        return self.audits.get(str(audit_id), '')

    @gl.public.view
    def get_counts(self) -> dict:
        return {'policies': int(self.policy_count), 'audits': int(self.audit_count)}
