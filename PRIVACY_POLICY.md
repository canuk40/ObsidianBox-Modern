# Privacy Policy
**ObsidianBox Modern**  
**Last Updated:** September 26, 2026  
**Effective Date:** September 26, 2026
---
## Introduction
ObsidianBox Modern ("we," "our," or "the App") is committed to protecting your privacy. This Privacy Policy explains how we handle information when you use our Android application.

**The short version:** the files, commands, and terminal history you work with never leave your device. We do use Google Firebase for crash reporting, basic usage analytics, and an anti-piracy check, and — if you're not a Pro subscriber or purchaser — Google AdMob to show ads. Full details below.
---
## Information We Do NOT Collect
Regardless of your Pro status, ObsidianBox Modern never collects, stores, transmits, or processes:
- Personal identification information (name, email, phone number)
- Contact information or your contacts list
- Browsing history
- Photos, media, or files (beyond what you explicitly process through ObsidianBox commands, which stays on-device)
- Your precise GPS location — see "Location Permission" below
---
## Information We Do Collect
### Automatically, via Google Firebase (all users)
- **Crash & error reports** (Firebase Crashlytics): when the app crashes or hits an unexpected error, a report is sent to Firebase containing the stack trace, device model, OS version, app version, and a random installation identifier. This is not tied to your name or email.
- **Basic usage analytics** (Firebase Analytics): standard app events (app opens, screen views) plus a small number of feature-specific events for the Watchdog monitoring feature (e.g. enabled/disabled, pass/fail results). No message content, file contents, or command text is ever included.
- **Performance data** (Firebase Performance Monitoring): app startup time and network request timing, used to catch slow or broken code paths.
- **Anti-piracy verification** (Firebase Cloud Functions + Google Play Integrity API): on startup, a Play Integrity token is sent to a Firebase Cloud Function to confirm the app was installed from a genuine Play Store build. This does not identify you personally.
- **Security blocklist updates** (Firebase Remote Config): the app periodically fetches an updated list of known-malicious plugin IDs. This is a one-way configuration fetch; nothing about your device or usage is required to receive it.

### Advertising (free users only)
- If you are **not** a Pro subscriber or Pro purchaser, ObsidianBox Modern shows interstitial ads via **Google AdMob** on screen transitions (frequency-capped). AdMob uses your device's **Advertising ID** to serve and measure ads — see Google's ad policies: https://policies.google.com/technologies/ads
- **Pro users (subscription or one-time purchase) never see ads and are excluded from AdMob entirely.**
---
## Location Permission
On Android 12 and earlier, reading the name of the Wi-Fi network you're connected to (used in Network Tools) requires the device's Location permission to be granted — this is an Android OS requirement, not something we chose. We do not read, store, or transmit your GPS coordinates; the permission is used only to display the connected Wi-Fi network's name on-device.
---
## Information That Stays on Your Device
The following information is stored **locally on your device only** and is never transmitted:
### App Preferences
- Terminal settings (font size, theme)
- User preferences and configurations
- Acceptance of Terms of Service and Disclaimers
### Command History
- Terminal command history (stored locally for your convenience)
- Automation module configurations
### Snapshots and Backups
- System snapshots created by the App remain on your device
- You control when to create, restore, or delete them
---
## Third-Party Services
### Google Play Billing
If you purchase Pro features, the transaction is handled entirely by Google Play. We do not have access to your payment information. Google's privacy policy governs that data: https://policies.google.com/privacy
### Google Firebase
Crash reporting, analytics, performance monitoring, remote config, and anti-piracy verification (see above) are provided by Google Firebase. Google's privacy policy: https://policies.google.com/privacy
### Google AdMob (free users only)
Ads are served by Google AdMob (see above). Google's ad-related policies: https://policies.google.com/technologies/ads
---
## Permissions Explained
ObsidianBox Modern may request the following permissions:
| Permission | Purpose | Data Sent |
|------------|---------|-----------|
| Root Access | Execute ObsidianBox commands at system level | None - all operations are local |
| Storage | Read/write files you explicitly work with | None - files stay on device |
| Location | Required by Android to read the connected Wi-Fi network name in Network Tools | None - GPS coordinates are never read or sent |
| Internet | Check for updates, Pro license verification, Firebase and AdMob services | See "Information We Do Collect" above |
---
## Data Security
Files, command history, and preferences you create in the App remain on your device under your control. Data sent to Firebase and AdMob is transmitted and secured under Google's own infrastructure and privacy practices (linked above).
For on-device security:
- Preferences are stored using Android's secure DataStore
- No sensitive data (purchase tokens, billing state) is written to logs
- Root operations are logged locally only
---
## Children's Privacy
ObsidianBox Modern is not directed at children under 13. The App requires technical knowledge of Linux/Unix systems and root access, making it unsuitable for children.
---
## Changes to This Policy
We may update this Privacy Policy occasionally. Changes will be posted to this page with an updated "Last Updated" date. Continued use of the App after changes constitutes acceptance of the new policy.
---
## Your Rights
You control all on-device data (files, command history, preferences, snapshots) directly, since it never leaves your device. For data held by Google on our behalf (Firebase and AdMob identifiers), Google's own privacy controls apply: https://myaccount.google.com/data-and-privacy
---
## Open Source
ObsidianBox Modern's source code is available at:  
https://github.com/canuk40/obsidianbox-modern
You can review exactly how the App handles your data.
---
## Contact
If you have questions about this Privacy Policy:
- **GitHub Issues:** https://github.com/canuk40/obsidianbox-modern/issues
- **Developer:** canuk40
---
## Summary
| Question | Answer |
|----------|--------|
| Do you collect personal data (name, email, etc.)? | **No** |
| Do you use crash reporting / analytics? | **Yes** (Firebase Crashlytics & Analytics) |
| Do you show ads? | **Yes, for free-tier users only** (Google AdMob) — Pro users see none |
| Do you sell data? | **No** |
| Where are my files and commands stored? | **On your device only** |
| Is the app open source? | **Yes** (safety/diagnostic layer) |
---
*We only collect what's needed to keep the app stable, secure, and (for free users) ad-supported — your files and commands never leave your device.*
