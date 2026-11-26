### CAWG metadata testing (MINOR)

- Add SDK 0.92.2 compatibility; require Rust 1.96 or newer and recommend current stable Rust.
- Update the locked transitive `webpki-root-certs` dependency from 1.0.7 to 1.0.12, addressing RUSTSEC-2026-0383 without forcing a direct dependency or broadly updating the graph.
- Migrate trust CLI/sidecar loading to SDK `trust.anchors` entries so removed settings are not silently ignored; retain existing configured anchors and verification.
- Add `--target cawg_author` and `--target cawg_person_identifier` using Schema.org JSON-LD in `cawg.metadata`.
- Keep `author` and `person_identifier` as explicit legacy CreativeWork tests with unchanged assertion fields and filename prefixes; do not silently convert existing jobs.
- Prefer `-t regex` with ordinary JSON manifest templates for additional CAWG metadata fields and alternative schemas such as Dublin Core. Support mutually exclusive `-m/--manifest` or `-c/--config`.
- Preserve literal dollar signs, quotes, backslashes, and JSON-escaped control characters in template payloads. Report batch failures through an unsuccessful exit status.
- Add CAWG samples and signed-asset regression tests to the existing pull-request unit suite; make sample generation template-first.
- This release covers CAWG metadata, not separately signed CAWG Identity assertions or credential-holder proof.

Release as 0.2.0 from the latest 0.1.x release (currently 0.1.6) using the existing semantic-version automation. The PR/squash title must include `(MINOR)` so the marker is present in the commit history. Version and CHANGELOG.md remain release-generated; these pending notes are consumed by the release workflow. Merging this PR prepares the release; publishing still requires the existing manual release-workflow dispatch.
