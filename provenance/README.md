# Release provenance

`compiler/provenance.py` emits the canonical `bash.provenance.json` release asset.
It binds the signed pack to `rules.lock`, the pinned upstream and BashLume compiler
Git trees, the exact compiler binary, all primary and support-source hashes, linked
per-command dependencies, and their SPDX license texts.

Release and CI jobs regenerate and verify this manifest from clean checkouts. No
wall-clock timestamp or absolute build path is included.
