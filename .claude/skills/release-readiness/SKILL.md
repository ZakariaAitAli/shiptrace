---
name: release-readiness
description: Checks whether a ShipTrace build is fit to release by collecting evidence for quality, security and supply-chain gates. Use before tagging a release or promoting an image. Reports only and never publishes.
disable-model-invocation: true
---

Assess release candidate: $ARGUMENTS

Report each item as `pass`, `fail` or `not verified`, with evidence. Never infer a pass.

1. CI is green on the exact commit; record the run URL.
2. Migrations reviewed; deployment order and rollback are written down.
3. No unresolved high or critical findings; accepted risks are named.
4. Image is identified by digest, runs non-root, and passes smoke tests.
5. `gh attestation verify` passes for provenance and SBOM; scanners are clean, or exceptions are
   justified with an expiry.
6. Backup and restore evidence is current.
7. Changelog and docs match behavior.

End with `READY` or `NOT READY` and the blockers. Pushing, tagging, promoting and deploying remain
owner actions.
