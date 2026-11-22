# CVE-2026-64560 audit sources

These are the native sources available for the 64560 assets.  They are
included for audit/reproducibility.  The release APK keeps the previously
validated 64560 binaries; build-binaries.ps1 compiles these sources into
`build/binaries/64560-audit/` and does not overwrite the release assets.

- `native/` — MagicRoot native sources for addrcalc / kaslr_slide / ko_patch /
  ksu_grant.
- `upstream-honeclick/` — forker and CVE-2026-64560 public/honeclick sources
  (Apache-2.0 / MIT attributions in THIRD_PARTY_NOTICES.md).
- `merge/` — cred_target/cred probe adaptation sources.

included from the older `MagicRoot-1.0.2/host/native` workspace.  The release
assets are kept as previously validated binaries; the build script can rebuild
audit copies from these sources.

