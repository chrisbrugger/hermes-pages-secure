(() => {
  const $ = (id) => document.getElementById(id);
  const app = document.querySelector('[data-secure-page]') || document.body;
  const form = $('form');
  const button = $('button');
  const statusEl = $('status');
  const passphraseEl = $('passphrase');
  const themeEl = $('theme');
  const unlock = $('unlock');
  const frame = $('frame');
  const payloadPath = app.dataset.payload || 'payload.json';
  const mode = app.dataset.mode || 'report';

  function setTheme(theme) {
    const allowed = new Set(['ledger', 'redline', 'obsidian', 'ember']);
    const raw = theme || localStorage.getItem('hermesPagesTheme') || 'ledger';
    const selected = allowed.has(raw) ? raw : 'ledger';
    document.documentElement.dataset.theme = selected;
    if (themeEl) themeEl.value = selected;
    localStorage.setItem('hermesPagesTheme', selected);
    return selected;
  }

  setTheme();
  if (themeEl) themeEl.addEventListener('change', () => setTheme(themeEl.value));

  function b64ToBytes(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  async function deriveKey(passphrase, salt, iterations) {
    const material = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  }

  async function decryptV1(payload, passphrase) {
    const salt = b64ToBytes(payload.salt);
    const iv = b64ToBytes(payload.iv);
    const ciphertext = b64ToBytes(payload.ciphertext);
    const key = await deriveKey(passphrase, salt, payload.iterations);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return new TextDecoder().decode(plaintext);
  }

  async function decryptV2(payload, passphrase) {
    if (!Array.isArray(payload.keys) || !payload.content) throw new Error('Unsupported encrypted payload.');
    const contentIv = b64ToBytes(payload.content.iv);
    const contentCiphertext = b64ToBytes(payload.content.ciphertext);
    let lastError = null;
    for (const entry of payload.keys) {
      try {
        const wrappingKey = await deriveKey(passphrase, b64ToBytes(entry.salt), entry.iterations || payload.iterations);
        const rawContentKey = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: b64ToBytes(entry.iv) },
          wrappingKey,
          b64ToBytes(entry.wrapped_key)
        );
        const contentKey = await crypto.subtle.importKey('raw', rawContentKey, { name: 'AES-GCM' }, false, ['decrypt']);
        const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: contentIv }, contentKey, contentCiphertext);
        return new TextDecoder().decode(plaintext);
      } catch (error) {
        lastError = error;
      }
    }
    throw lastError || new Error('Could not decrypt with this passphrase.');
  }

  async function decryptPayload(passphrase) {
    const payload = await fetch(payloadPath, { cache: 'no-store' }).then((response) => {
      if (!response.ok) throw new Error('Could not load encrypted payload.');
      return response.json();
    });
    if (payload.v === 1) return decryptV1(payload, passphrase);
    if (payload.v === 2) return decryptV2(payload, passphrase);
    throw new Error('Unsupported encrypted payload.');
  }

  function injectTheme(html, theme) {
    const safeTheme = String(theme || 'ledger').replace(/[^a-z0-9_-]/gi, '');
    if (/<html\b/i.test(html)) {
      return html.replace(/<html\b([^>]*)>/i, (match, attrs) => {
        if (/data-theme=/i.test(attrs)) return `<html${attrs.replace(/data-theme=["'][^"']*["']/i, `data-theme="${safeTheme}"`)}>`;
        return `<html data-theme="${safeTheme}"${attrs}>`;
      });
    }
    return `<!doctype html><html data-theme="${safeTheme}"><head><meta charset="utf-8"></head><body>${html}</body></html>`;
  }

  function showHtml(html) {
    const theme = setTheme(themeEl ? themeEl.value : undefined);
    frame.srcdoc = injectTheme(html, theme);
    frame.style.display = 'block';
    unlock.style.display = 'none';
    document.title = mode === 'index' ? 'Hermes Secure Report Index' : 'Decrypted Hermes Report';
  }

  function setStatus(text, klass = '') {
    statusEl.className = `status ${klass}`.trim();
    statusEl.textContent = text;
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    button.disabled = true;
    setStatus('Decrypting…');
    try {
      const html = await decryptPayload(passphraseEl.value);
      setStatus('Decrypted.', 'good');
      showHtml(html);
    } catch (error) {
      setStatus('Could not decrypt. Check the passphrase.', 'bad');
      button.disabled = false;
    }
  });
})();
