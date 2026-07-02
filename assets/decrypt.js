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
  const THEME_KEY = 'hermesPagesTheme';
  const MASTER_KEY = 'hermesPagesMasterPassphrase';
  const THEMES = [
    ['ledger', 'Ledger'],
    ['redline', 'Redline'],
    ['obsidian', 'Obsidian'],
    ['ember', 'Ember'],
  ];
  const allowedThemes = new Set(THEMES.map(([value]) => value));
  let currentHtml = '';
  let viewerThemeEl = null;
  let clearMasterButton = null;
  let viewerStatusEl = null;

  function normalizeTheme(theme) {
    const raw = theme || localStorage.getItem(THEME_KEY) || 'ledger';
    return allowedThemes.has(raw) ? raw : 'ledger';
  }

  function setTheme(theme) {
    const selected = normalizeTheme(theme);
    document.documentElement.dataset.theme = selected;
    if (themeEl) themeEl.value = selected;
    if (viewerThemeEl) viewerThemeEl.value = selected;
    localStorage.setItem(THEME_KEY, selected);
    applyFrameTheme(selected);
    return selected;
  }

  function createViewerToolbar() {
    let toolbar = $('viewer-toolbar');
    if (toolbar) return toolbar;
    toolbar = document.createElement('div');
    toolbar.id = 'viewer-toolbar';
    toolbar.className = 'viewer-toolbar';
    toolbar.setAttribute('aria-label', 'Report controls');

    const label = document.createElement('label');
    label.setAttribute('for', 'viewer-theme');
    label.textContent = 'Theme';

    viewerThemeEl = document.createElement('select');
    viewerThemeEl.id = 'viewer-theme';
    viewerThemeEl.name = 'viewer-theme';
    for (const [value, text] of THEMES) {
      const option = document.createElement('option');
      option.value = value;
      option.textContent = text;
      viewerThemeEl.appendChild(option);
    }
    viewerThemeEl.addEventListener('change', () => setTheme(viewerThemeEl.value));

    clearMasterButton = document.createElement('button');
    clearMasterButton.id = 'clear-master';
    clearMasterButton.type = 'button';
    clearMasterButton.textContent = 'Forget master passphrase';
    clearMasterButton.addEventListener('click', () => {
      localStorage.removeItem(MASTER_KEY);
      updateMasterButtonState(false);
      setViewerStatus('Saved master passphrase cleared.');
    });

    viewerStatusEl = document.createElement('span');
    viewerStatusEl.id = 'viewer-status';
    viewerStatusEl.className = 'viewer-status';

    toolbar.append(label, viewerThemeEl, clearMasterButton, viewerStatusEl);
    document.body.insertBefore(toolbar, document.body.firstChild);
    return toolbar;
  }

  function updateMasterButtonState(hasSavedMaster = Boolean(localStorage.getItem(MASTER_KEY))) {
    if (!clearMasterButton) return;
    clearMasterButton.disabled = !hasSavedMaster;
    clearMasterButton.title = hasSavedMaster
      ? 'Remove the locally saved master passphrase from this browser'
      : 'No master passphrase is saved in this browser';
  }

  function setViewerStatus(text) {
    if (!viewerStatusEl) return;
    viewerStatusEl.textContent = text || '';
    if (text) window.setTimeout(() => {
      if (viewerStatusEl.textContent === text) viewerStatusEl.textContent = '';
    }, 3600);
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
    return { html: new TextDecoder().decode(plaintext), keyLabel: 'legacy' };
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
        return { html: new TextDecoder().decode(plaintext), keyLabel: entry.label || 'unknown' };
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
    const safeTheme = normalizeTheme(String(theme || 'ledger').replace(/[^a-z0-9_-]/gi, ''));
    if (/<html\b/i.test(html)) {
      return html.replace(/<html\b([^>]*)>/i, (match, attrs) => {
        if (/data-theme=/i.test(attrs)) return `<html${attrs.replace(/data-theme=["'][^"']*["']/i, `data-theme="${safeTheme}"`)}>`;
        return `<html data-theme="${safeTheme}"${attrs}>`;
      });
    }
    return `<!doctype html><html data-theme="${safeTheme}"><head><meta charset="utf-8"></head><body>${html}</body></html>`;
  }

  function applyFrameTheme(theme) {
    if (!frame || !frame.contentDocument) return;
    try {
      frame.contentDocument.documentElement.dataset.theme = normalizeTheme(theme);
    } catch (error) {
      // The iframe uses srcdoc and same-origin sandboxing, but ignore if a browser blocks access.
    }
  }

  function showHtml(result, passphrase, { fromSavedMaster = false } = {}) {
    const html = typeof result === 'string' ? result : result.html;
    const keyLabel = typeof result === 'string' ? 'unknown' : result.keyLabel;
    currentHtml = html;
    const theme = setTheme(themeEl ? themeEl.value : undefined);
    frame.srcdoc = injectTheme(currentHtml, theme);
    frame.style.display = 'block';
    unlock.style.display = 'none';
    document.body.classList.add('is-unlocked');
    createViewerToolbar();
    setTheme(theme);
    document.title = mode === 'index' ? 'Hermes Secure Report Index' : 'Decrypted Hermes Report';

    if (keyLabel === 'master' && passphrase) {
      localStorage.setItem(MASTER_KEY, passphrase);
      updateMasterButtonState(true);
      setViewerStatus(fromSavedMaster ? 'Unlocked with saved master passphrase.' : 'Master passphrase saved in this browser.');
    } else {
      updateMasterButtonState();
      if (fromSavedMaster) setViewerStatus('Unlocked with saved master passphrase.');
    }
  }

  function setStatus(text, klass = '') {
    statusEl.className = `status ${klass}`.trim();
    statusEl.textContent = text;
  }

  async function unlockWithPassphrase(passphrase, options = {}) {
    if (!passphrase) throw new Error('Missing passphrase.');
    const result = await decryptPayload(passphrase);
    showHtml(result, passphrase, options);
    return result;
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    button.disabled = true;
    setStatus('Decrypting…');
    try {
      await unlockWithPassphrase(passphraseEl.value);
      setStatus('Decrypted.', 'good');
    } catch (error) {
      setStatus('Could not decrypt. Check the passphrase.', 'bad');
      button.disabled = false;
    }
  });

  async function trySavedMaster() {
    const saved = localStorage.getItem(MASTER_KEY);
    if (!saved) return;
    button.disabled = true;
    setStatus('Unlocking with saved master passphrase…');
    try {
      await unlockWithPassphrase(saved, { fromSavedMaster: true });
      setStatus('Decrypted.', 'good');
    } catch (error) {
      localStorage.removeItem(MASTER_KEY);
      button.disabled = false;
      setStatus('Saved master passphrase no longer works. Please enter it again.', 'bad');
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', trySavedMaster, { once: true });
  } else {
    trySavedMaster();
  }
})();
