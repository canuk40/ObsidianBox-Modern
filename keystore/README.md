# ObsidianBox Modern — release signing keystore

**⚠️ This repo must stay PRIVATE. This folder contains the private key and cleartext
passwords that control every future Play Store update for `com.busyboxmodern.app`.**

## What's here

- `obsidianbox-release.jks` — PKCS12 keystore, alias `obsidianbox-release`, RSA 4096,
  self-signed, valid 30 years (generated 2026-08-15, expires 2056-08-14).
- `keystore.properties` — `storeFile` / `storePassword` / `keyAlias` / `keyPassword` for
  Gradle to sign release builds. Referenced from `app/build.gradle.kts` via
  `rootProject.file("keystore/keystore.properties")`.
- `obsidianbox-release-upload-cert.pem` — the public certificate only (safe to share,
  e.g. for Play Console's upload-key-registration/reset flow, Digital Asset Links, etc.).

## Backstory

The original keystore was lost in a computer wipe. This one was generated fresh on
2026-08-15 and registered with Google Play as the new **upload key** via Play Console's
"Request upload key reset" flow (Play App Signing is enrolled, so Google separately holds
the actual **app signing key** — this keystore only needs to match the *upload* key
certificate, not the app signing key certificate). The reset had a ~48-hour Google-enforced
security hold before the new key became valid for uploads.

## If this is ever lost again

1. Generate a new keystore (`keytool -genkeypair`, PKCS12, RSA 4096+).
2. Export the public cert (`keytool -export -rfc`).
3. In Play Console → App integrity → App signing → "Request upload key reset", upload
   that cert.
4. Wait out Google's security hold (a fixed window shown in their confirmation email —
   it's not an indefinite manual review).
5. Update `keystore.properties` to point at the new file, rebuild, re-back-up here.

## To use this keystore to sign a release build

Copy this whole `keystore/` folder to the project root (sibling of `app/`) in
`D:\OPEN IN ANDROID STUDIO - ObsidianBox Modern\keystore\`, then:

```bash
./gradlew.bat :app:bundleRelease --stacktrace --no-daemon
```
