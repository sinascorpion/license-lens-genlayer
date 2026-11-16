# LicenseLens

LicenseLens is an experimental GenLayer Intelligent Contract for reproducible review of license declarations in a chosen set of exact npm package versions. A contract owner creates immutable allow/deny policies; anyone can ask validators to fetch and evaluate up to eight npm registry version records against one policy and store the resulting evidence on chain.

## Why it exists

Teams often exchange license compliance reports without sharing a reproducible account of which policy and registry metadata produced them. LicenseLens makes those inputs and the result public. This is a policy decision aid, not legal advice or proof of compliance.

## How it works

1. The owner calls `create_policy(name, allow_json, deny_json)`. Each list contains exact SPDX-like identifiers; the lists must be disjoint and policies cannot be edited.
2. Anyone calls `audit_packages(policy_id, packages_json)` with one to eight unique objects such as `[{"name":"lodash","version":"4.17.21"}]`. Only exact versions are accepted.
3. The contract uses `gl.eq_principle.strict_eq` to have validators independently query `https://registry.npmjs.org/<name>/<version>`. It checks returned package identity and version and extracts the declared license and distribution integrity. Validators must agree on the entire normalized result, including every individual verdict, before a record is committed.
4. `get_policy`, `get_audit` and `get_counts` expose policies and snapshots. An audit returns its policy ID, requester, normalized package/version pairs, observed license, registry integrity value, individual result and overall result.

The evaluator implements `AND`, `OR`, parentheses, and three-valued logic over explicit allow and deny sets. `AND` is denied if any operand is denied, allowed only if all are allowed, and unknown otherwise. `OR` is allowed if any option is allowed, denied only if all are denied, and unknown otherwise. Unknown identifiers, missing metadata, malformed expressions, `WITH` exceptions and unsupported syntax yield `UNKNOWN` where they cannot be resolved; an explicit allowed alternative in an `OR` can still establish `ALLOW`. An audit is `DENY` if any package is denied, otherwise `UNKNOWN` if any is unknown, otherwise `ALLOW`. An unavailable or mismatched registry response aborts without creating a record.

## Scope and limitations

- Policy decisions reflect the owner's choices; they are not independent legal conclusions. Package publishers control npm metadata, and the registry is a single upstream source.
- The submitted list is user-selected. The contract does not resolve transitive dependencies, check a lockfile, inspect a tarball or verify an installed application. The registry integrity field is recorded but the tarball is not downloaded or independently verified.
- Registry metadata and license declarations can change. Records are historical observations, not a live guarantee. Consensus does not prove that the registry or publisher is truthful.
- Complex SPDX expressions containing exceptions or legacy license strings may be unresolved. An SPDX-like identifier is not checked against a current SPDX registry. The contract is not audited and should not be used as the sole basis for compliance decisions.
- Studio-dev is a test network and may reset.

## Run tests

`python -m unittest test_contract -v` runs local mock tests. These tests do not demonstrate actual validator execution or network access. A deployed address and live transaction evidence should be added only after verification.

## Studio-dev deployment

- Contract: [0x0abC6d05827792Bb64558C0a40156d1BCf927Bb2](https://explorer-studio-dev.genlayer.com/address/0x0abC6d05827792Bb64558C0a40156d1BCf927Bb2)
- [Deployment transaction](https://explorer-studio-dev.genlayer.com/tx/0x9e89e3ba1236cc88161c7300010d413fb99dca15fd27bb9ca5602aadeca4e924) finalized successfully.
- [Policy creation transaction](https://explorer-studio-dev.genlayer.com/tx/0xbd1b7ee0e69569acbb9a71b6eea16bcc960dc26656104a6b688d6576cd526207) finalized successfully and policy 1 was read back.
- [Live npm audit transaction](https://explorer-studio-dev.genlayer.com/tx/0x1746aa516ff662793cecaf6db8d03ea5247b70141ca375cebd93fab689bdedb6) finalized successfully with five initial validators. Audit 1 was read back with `ALLOW` for express 4.18.2 and lodash 4.17.21 under policy 1; both registry declarations were MIT.
