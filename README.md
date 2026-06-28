# Hermes Pages Secure

Public static host for encrypted Hermes report bundles.

This repository intentionally contains only encrypted report payloads and a browser-side decrypt UI. Plaintext report sources live in the private `chrisbrugger/hermes-pages` repository.

Public site: <https://chrisbrugger.github.io/hermes-pages-secure/>

## Security model

- Report HTML and inlined images/assets are encrypted before being committed here.
- Decryption happens locally in the reader's browser with a passphrase shared out-of-band.
- Anyone can download encrypted payloads, so passphrases must be strong.
- Revocation requires republishing with a new passphrase or deleting the page.
