# Signed dependency cache

`build.yml` uses ordinary `actions/cache` restore/save steps, not a mirror:

- The original FFmpeg ZIP is cached by version, architecture and pinned upstream
  release-asset SHA256. Both hits and downloads are hash-checked before extraction;
  update both hashes when updating `FFMPEG_VERSION`. Only an output copy is signed.
- Only trusted `push` builds of `ShareX/ShareX: test-signing`, excluding Debug and
  MicrosoftStoreDebug, may restore/save signed dependencies or use Azure signing.
- The signed overlay contains top-level third-party EXE/DLL files from the main
  build output, keyed by **original full-file SHA256/name**. It never changes the
  NuGet global packages folder, caches ShareX build products, or scans other trees.
  Valid upstream signatures are preserved; invalid signatures fail the build.
- Each immutable cache key includes OS, architecture, configuration, a policy hash
  (helper contents plus Azure endpoint/account/profile), and the complete original
  dependency inventory hash. A prefix fallback reuses unchanged entries when
  dependencies change; missing entries alone are staged for Azure signing.
- Hits and newly signed files must have valid Windows Authenticode signatures and
  the publisher of the freshly Azure-signed `ShareX.exe` (not a rotating certificate
  thumbprint). A strict normalized PE comparison binds them to the actual source:
  only checksum, security-directory fields, terminal certificate data and signing
  alignment padding may differ. No cached manifest is trusted. Unexpected PE
  layouts/content/publishers fail closed instead of silently signing replacements.
- Fresh ShareX binaries, Steam launcher and setup remain signed every applicable
  build, with signature/publisher verification. Bump `signed-dependencies-v1` in
  the key-generation step when changing the signing action, digest/timestamp
  settings, or revocation policy to force re-signing. Corrupt immutable entries
  must be deleted or invalidated, not silently accepted.

Parallel cold-cache matrix jobs can download/sign the same inputs independently.
Configuration isolation is intentional; subsequent builds reuse their respective
caches. No global serialization or signing service beyond the existing action is
introduced.

## Tests

Run with PowerShell 7:

```powershell
pwsh -NoProfile -File .github/scripts/SignedDependencies.Tests.ps1
```

The credential-free tests run in the x64 Debug CI leg. They exercise real file
inventory, hashing, staging, copying and comparison using synthetic PE fixtures
and a mocked Authenticode verifier/external signer. They cover cold/warm/changed
inputs, upstream signature preservation, ShareX exclusion, and rejection of
invalid signatures, unrelated signed contents and unexpected publishers.

These tests do **not** prove Windows certificate-chain/revocation/timestamp trust
or Azure authentication. A trusted Windows `test-signing` run is needed to verify
those integrations (cold run, unchanged warm run, then one dependency upgrade).
For an additional Linux smoke test, normalize a real PE before/after signing a
copy with `osslsigncode` and a disposable self-signed certificate; the helper's
`Get-PeContentHash` values must match. This validates actual PE signing layout, not
Windows trust of the disposable certificate.
