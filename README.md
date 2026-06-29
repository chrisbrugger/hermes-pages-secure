# Hermes Pages Secure

Public static host for encrypted Hermes report bundles.

This repository intentionally contains only encrypted report payloads, shared theme/decrypt assets, and generic unlock shells. Plaintext report sources and the plaintext report manifest live in the private `chrisbrugger/hermes-pages` repository.

Public site: <https://chrisbrugger.github.io/hermes-pages-secure/>

## Security model

- Report HTML and inlined local images/assets are encrypted before being committed here.
- Each report has a random content key.
- That content key is wrapped for both:
  - the per-report passphrase shared with recipients
  - the owner's master passphrase
- The root overview is encrypted too; report headlines/navigation are visible only after master unlock.
- Decryption happens locally in the browser with WebCrypto PBKDF2 + AES-GCM.
- Anyone can download encrypted payloads, so passphrases must be strong.
- Revocation requires deleting the page or republishing with a new passphrase.

## Theme system

Shared assets live under `assets/`:

- `assets/shell.css` — unlock screen themes
- `assets/report.css` — decrypted report/index themes
- `assets/decrypt.js` — shared decrypt + theme selector logic

Future visual changes should usually be made in these files instead of republishing every report.
