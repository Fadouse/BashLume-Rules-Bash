# BashLume Rules — Bash

GPL-2.0-or-later completion-rule pack derived from [`scop/bash-completion`](https://github.com/scop/bash-completion) for the Rust-native [BashLume](https://github.com/Fadouse/BashLume) Completion IR.

This repository is intentionally separate from the BashLume engine. Its release artifact is pure-data `bash.blp`; BashLume does not source or execute the upstream Bash scripts at runtime.

## Stable gate

No Stable artifact may be published until all completion files and registrations in the pinned upstream baseline compile with:

- zero unsupported constructs
- zero stale commands
- exact normalized differential parity in hermetic fixtures
- complete provenance and GPL attribution

Generic filename completion is not counted as conversion.

## Development

```bash
python3 compiler/sync.py --channel stable --checkout .work/upstream
python3 compiler/compile.py --upstream .work/upstream --output build/bash.json
bashlume-pack build build/bash.json build/bash.blp
python3 tests/coverage.py --upstream .work/upstream --spec build/bash.json
python3 tests/differential.py --upstream .work/upstream --pack build/bash.blp
```

`rules.lock` pins Stable and Edge upstream commits. Workflows only create update PRs; they never push generated upstream changes directly to `main`.

## Signing

`keys/official.pub` is the official Ed25519 verification key (key ID `cc1bf0e554afb952f1e30a66f550b57bf0b687a629097a5efcfcf58d6c4171de`). The private key exists only in the protected `BASHLUME_SIGNING_KEY` GitHub Actions secret; release jobs fail closed when it is unavailable.

Copyright © 2026 Fadouse and the respective bash-completion contributors. See `LICENSE`, `COPYRIGHT`, and generated provenance manifests.
