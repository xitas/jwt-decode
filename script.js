(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const enc = new TextEncoder();
  const SAMPLE_SECRET = 'demo-secret';

  const el = {
    token: $('token'), parts: $('parts'), status: $('status'), warnings: $('warnings'),
    btnSample: $('btnSample'), btnClear: $('btnClear'),
    headerOut: $('headerOut').querySelector('code'), payloadOut: $('payloadOut').querySelector('code'), sigOut: $('sigOut').querySelector('code'),
    sigMeta: $('sigMeta'), claimsPane: $('claimsPane'), claims: $('claims'),
    copyHeader: $('copyHeader'), copyPayload: $('copyPayload'),
    key: $('key'), keyLabel: $('keyLabel'), keyHint: $('keyHint'), b64: $('b64'), b64row: $('b64row'),
    verifyAlg: $('verifyAlg'), verifyResult: $('verifyResult')
  };

  /* ---------- Base64URL ---------- */
  class UserError extends Error {}

  function b64urlToBytes(s) {
    if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) throw new UserError('not valid Base64URL');
    let b = s.replace(/-/g, '+').replace(/_/g, '/');
    while (b.length % 4) b += '=';
    const bin = atob(b);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToB64url(bytes) {
    let bin = '';
    bytes.forEach((b) => { bin += String.fromCharCode(b); });
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

  function parsePart(text, name) {
    let json;
    try {
      json = new TextDecoder('utf-8', { fatal: true }).decode(b64urlToBytes(text));
    } catch (e) {
      throw new UserError('The ' + name + ' is not valid Base64URL text.');
    }
    try {
      return JSON.parse(json);
    } catch (e) {
      throw new UserError('The ' + name + ' decodes to text that is not valid JSON.');
    }
  }

  /* ---------- Decoding ---------- */
  function decodeToken(raw) {
    const t = raw.trim().replace(/^bearer\s+/i, '').replace(/\s+/g, '');
    if (!t) return { empty: true };
    const parts = t.split('.');
    if (parts.length === 5) return { error: 'This looks like an encrypted token (JWE) with five parts. Only signed tokens (JWS) with three parts can be decoded here.' };
    if (parts.length !== 3) return { error: 'A JWT has 3 parts separated by dots, but this has ' + parts.length + '.' };
    try {
      const header = parsePart(parts[0], 'header');
      if (!isObject(header)) return { error: 'The header must be a JSON object.' };
      const payload = parsePart(parts[1], 'payload');
      if (!isObject(payload)) return { error: 'The payload must be a JSON object of claims.' };
      if (!/^[A-Za-z0-9_-]*$/.test(parts[2])) return { error: 'The signature is not valid Base64URL text.' };
      return { token: t, parts, header, payload };
    } catch (e) {
      if (e instanceof UserError) return { error: e.message };
      throw e;
    }
  }

  /* ---------- Time ---------- */
  const isNum = (v) => typeof v === 'number' && isFinite(v);

  function relative(ms) {
    const diff = ms - Date.now();
    const abs = Math.abs(diff) / 1000;
    if (abs < 1) return 'just now';
    let n; let u;
    if (abs < 60) { n = Math.round(abs); u = 'second'; }
    else if (abs < 3600) { n = Math.round(abs / 60); u = 'minute'; }
    else if (abs < 86400) { n = Math.round(abs / 3600); u = 'hour'; }
    else if (abs < 86400 * 60) { n = Math.round(abs / 86400); u = 'day'; }
    else if (abs < 86400 * 730) { n = Math.round(abs / 86400 / 30.44); u = 'month'; }
    else { n = Math.round(abs / 86400 / 365.25); u = 'year'; }
    const text = n + ' ' + u + (n === 1 ? '' : 's');
    return diff >= 0 ? 'in ' + text : text + ' ago';
  }

  function timeInfo(seconds) {
    const d = new Date(seconds * 1000);
    if (isNaN(d.getTime())) return null;
    return {
      local: d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' }),
      utc: d.toISOString().replace('.000Z', 'Z'),
      rel: relative(seconds * 1000)
    };
  }

  function timeStatus(payload) {
    const now = Date.now();
    if (isNum(payload.exp) && now >= payload.exp * 1000) return 'expired';
    if (isNum(payload.nbf) && now < payload.nbf * 1000) return 'notyet';
    return 'active';
  }

  /* ---------- Rendering ---------- */
  const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const TOKEN = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false)\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;

  function highlight(text) {
    return esc(text).replace(TOKEN, (m, str, colon, bool) => {
      if (str) return colon ? '<span class="k">' + str + '</span>' + colon : '<span class="s">' + str + '</span>';
      if (bool) return '<span class="b">' + m + '</span>';
      if (m === 'null') return '<span class="z">null</span>';
      return '<span class="n">' + m + '</span>';
    });
  }

  function placeholder(node, text) {
    node.innerHTML = '';
    const span = document.createElement('span');
    span.className = 'placeholder';
    span.textContent = text;
    node.appendChild(span);
  }

  function setStatus(state, pill, text) {
    el.status.dataset.state = state;
    el.status.innerHTML = '<span class="pill"></span><span class="msg"></span>';
    el.status.querySelector('.pill').textContent = pill;
    el.status.querySelector('.msg').textContent = text;
  }

  function renderParts(parts) {
    el.parts.innerHTML = '';
    const cls = ['h', 'p', 'g'];
    parts.forEach((p, i) => {
      const span = document.createElement('span');
      span.className = cls[i];
      span.textContent = p;
      el.parts.appendChild(span);
      if (i < 2) {
        const dot = document.createElement('span');
        dot.className = 'dot';
        dot.textContent = '.';
        el.parts.appendChild(dot);
      }
    });
    el.parts.hidden = false;
  }

  function warningsFor(d) {
    const out = [];
    const alg = typeof d.header.alg === 'string' ? d.header.alg : '';
    if (!alg) out.push('The header has no "alg" value, so the signing algorithm is unknown.');
    if (alg.toLowerCase() === 'none') out.push('This token is unsecured: its algorithm is "none", so it has no signature. Never trust it for authentication.');
    if (!('exp' in d.payload)) out.push('There is no "exp" claim, so this token never expires.');
    ['exp', 'nbf', 'iat'].forEach((k) => {
      if (!(k in d.payload)) return;
      const v = d.payload[k];
      if (!isNum(v)) out.push('The "' + k + '" claim should be a number of seconds, but it is ' + (typeof v) + '.');
      else if (v > 1e11) out.push('The "' + k + '" claim looks like milliseconds. JWT times are in seconds.');
    });
    return out;
  }

  const CLAIM_NAMES = [
    ['iss', 'Issuer'], ['sub', 'Subject'], ['aud', 'Audience'],
    ['exp', 'Expires'], ['nbf', 'Not valid before'], ['iat', 'Issued at'], ['jti', 'Token ID']
  ];

  function renderClaims(payload) {
    el.claims.innerHTML = '';
    let count = 0;
    CLAIM_NAMES.forEach(([key, label]) => {
      if (!(key in payload)) return;
      count++;
      const v = payload[key];
      const dt = document.createElement('dt');
      dt.textContent = label;
      const code = document.createElement('code');
      code.textContent = key;
      dt.appendChild(code);

      const dd = document.createElement('dd');
      if (['exp', 'nbf', 'iat'].includes(key) && isNum(v) && timeInfo(v)) {
        const info = timeInfo(v);
        dd.appendChild(document.createTextNode(info.local));
        if (key === 'exp' || key === 'nbf') {
          const st = timeStatus(payload);
          if (key === 'exp' && st === 'expired') dd.appendChild(tag('Expired', 'bad'));
          else if (key === 'nbf' && st === 'notyet') dd.appendChild(tag('Not active yet', 'wait'));
        }
        const sub = document.createElement('span');
        sub.className = 'sub';
        sub.textContent = info.utc + ' · ' + info.rel;
        dd.appendChild(sub);
      } else {
        dd.textContent = Array.isArray(v) ? v.join(', ') : (typeof v === 'object' ? JSON.stringify(v) : String(v));
      }
      el.claims.append(dt, dd);
    });
    el.claimsPane.hidden = count === 0;
  }

  function tag(text, kind) {
    const s = document.createElement('span');
    s.className = 'tag ' + (kind || '');
    s.textContent = text;
    return s;
  }

  function renderWarnings(list) {
    el.warnings.innerHTML = '';
    list.forEach((w) => {
      const li = document.createElement('li');
      li.textContent = w;
      el.warnings.appendChild(li);
    });
    el.warnings.hidden = list.length === 0;
  }

  function renderStatus(d) {
    const st = timeStatus(d.payload);
    const p = d.payload;
    if (st === 'expired') {
      const info = timeInfo(p.exp);
      setStatus('warn', 'Expired', 'This token expired ' + (info ? info.rel + ' (' + info.local + ')' : '') + '. The signature is not checked unless you enter a key.');
    } else if (st === 'notyet') {
      const info = timeInfo(p.nbf);
      setStatus('warn', 'Not active yet', 'This token becomes valid ' + (info ? info.rel + ' (' + info.local + ')' : '') + '.');
    } else if (isNum(p.exp) && timeInfo(p.exp)) {
      setStatus('ok', 'Decoded', 'The token is well formed and expires ' + timeInfo(p.exp).rel + '. The signature is not checked unless you enter a key.');
    } else {
      setStatus('ok', 'Decoded', 'The token is well formed. The signature is not checked unless you enter a key.');
    }
  }

  /* ---------- State ---------- */
  let cur = null;      // last successfully decoded token
  let headerText = '';
  let payloadText = '';

  function update() {
    const d = decodeToken(el.token.value);

    if (d.empty) {
      cur = null;
      el.parts.hidden = true;
      renderWarnings([]);
      setStatus('empty', 'Ready', 'Paste a token on the left to begin.');
      placeholder(el.headerOut, 'The decoded header appears here.');
      placeholder(el.payloadOut, 'The decoded payload appears here.');
      placeholder(el.sigOut, 'The signature appears here.');
      el.sigMeta.textContent = '';
      el.claimsPane.hidden = true;
      headerText = payloadText = '';
      updateKeyUi();
      verify();
      return;
    }

    if (d.error) {
      cur = null;
      el.parts.hidden = true;
      renderWarnings([]);
      setStatus('invalid', 'Invalid', d.error);
      placeholder(el.headerOut, 'Fix the token to see the header.');
      placeholder(el.payloadOut, 'Fix the token to see the payload.');
      placeholder(el.sigOut, '');
      el.sigMeta.textContent = '';
      el.claimsPane.hidden = true;
      headerText = payloadText = '';
      updateKeyUi();
      verify();
      return;
    }

    cur = d;
    headerText = JSON.stringify(d.header, null, 2);
    payloadText = JSON.stringify(d.payload, null, 2);
    el.headerOut.innerHTML = highlight(headerText);
    el.payloadOut.innerHTML = highlight(payloadText);

    if (d.parts[2]) {
      el.sigOut.textContent = d.parts[2];
      el.sigMeta.textContent = b64urlToBytes(d.parts[2]).length + ' bytes';
    } else {
      placeholder(el.sigOut, 'This token has no signature.');
      el.sigMeta.textContent = 'empty';
    }

    renderParts(d.parts);
    renderClaims(d.payload);
    renderWarnings(warningsFor(d));
    renderStatus(d);
    updateKeyUi();
    verify();
  }

  /* Refresh the "expires in" wording as time passes. */
  setInterval(() => {
    if (!cur) return;
    renderClaims(cur.payload);
    renderStatus(cur);
  }, 30000);

  /* ---------- Signature check ---------- */
  const ALG = /^(HS|RS|PS|ES)(256|384|512)$/;
  const CURVES = { 256: 'P-256', 384: 'P-384', 512: 'P-521' };

  function updateKeyUi() {
    const alg = cur && typeof cur.header.alg === 'string' ? cur.header.alg : '';
    const m = ALG.exec(alg);
    el.verifyAlg.textContent = alg ? 'alg: ' + alg : '';
    const isHmac = !m || m[1] === 'HS';
    el.keyLabel.textContent = isHmac ? 'Secret' : 'Public key (PEM)';
    el.key.placeholder = isHmac ? 'Enter the secret used to sign the token' : '-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----';
    el.b64row.hidden = !(m && m[1] === 'HS');
    el.keyHint.textContent = isHmac
      ? 'The secret is used exactly as typed, including spaces.'
      : 'Paste the public key, never the private key. Use the "BEGIN PUBLIC KEY" format.';
  }

  function pemToDer(pem) {
    if (/PRIVATE KEY/.test(pem)) throw new UserError('That looks like a private key. Paste the public key instead, which starts with "-----BEGIN PUBLIC KEY-----".');
    if (/BEGIN CERTIFICATE/.test(pem)) throw new UserError('That is a certificate. Paste the public key from it instead (for example with: openssl x509 -pubkey -noout).');
    if (/BEGIN RSA PUBLIC KEY/.test(pem)) throw new UserError('That is an older PKCS#1 key. Convert it to the "BEGIN PUBLIC KEY" format (for example with: openssl rsa -RSAPublicKey_in -pubout).');
    const m = /-----BEGIN PUBLIC KEY-----([\s\S]*?)-----END PUBLIC KEY-----/.exec(pem);
    if (!m) throw new UserError('Paste a public key that starts with "-----BEGIN PUBLIC KEY-----".');
    try {
      const bin = atob(m[1].replace(/\s+/g, ''));
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    } catch (e) {
      throw new UserError('The public key could not be read. Check that it was copied completely.');
    }
  }

  async function checkSignature(d, keyText, secretIsB64) {
    const alg = d.header.alg;
    const m = ALG.exec(typeof alg === 'string' ? alg : '');
    if (!m) throw new UserError('Signature checks are not supported for alg "' + alg + '". Supported: HS, RS, PS and ES with 256, 384 or 512.');
    if (!window.crypto || !crypto.subtle) throw new UserError('Signature checks need a secure page (https or localhost).');

    const type = m[1];
    const bits = m[2];
    const hash = 'SHA-' + bits;
    const data = enc.encode(d.parts[0] + '.' + d.parts[1]);
    let sig;
    try { sig = b64urlToBytes(d.parts[2]); } catch (e) { throw new UserError('The signature is not valid Base64URL text.'); }
    if (!sig.length) throw new UserError('This token has no signature to check.');

    try {
      if (type === 'HS') {
        let raw;
        try { raw = secretIsB64 ? b64urlToBytes(keyText.trim()) : enc.encode(keyText); } catch (e) { throw new UserError('The secret is not valid Base64URL text.'); }
        const key = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash }, false, ['verify']);
        return crypto.subtle.verify('HMAC', key, sig, data);
      }
      const der = pemToDer(keyText);
      if (type === 'RS') {
        const key = await crypto.subtle.importKey('spki', der, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['verify']);
        return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, data);
      }
      if (type === 'PS') {
        const key = await crypto.subtle.importKey('spki', der, { name: 'RSA-PSS', hash }, false, ['verify']);
        return crypto.subtle.verify({ name: 'RSA-PSS', saltLength: Number(bits) / 8 }, key, sig, data);
      }
      const key = await crypto.subtle.importKey('spki', der, { name: 'ECDSA', namedCurve: CURVES[bits] }, false, ['verify']);
      return crypto.subtle.verify({ name: 'ECDSA', hash }, key, sig, data);
    } catch (e) {
      if (e instanceof UserError) throw e;
      throw new UserError('This key cannot be used with ' + alg + '. Check that the key type matches the algorithm.');
    }
  }

  function setVerify(state, text) {
    el.verifyResult.dataset.state = state;
    el.verifyResult.textContent = text;
  }

  let verifyRun = 0;
  async function verify() {
    const run = ++verifyRun;
    if (!cur) { setVerify('idle', 'Decode a token first, then enter a key to check the signature.'); return; }
    if (!el.key.value.trim()) { setVerify('idle', 'Enter a key to check the signature.'); return; }
    try {
      const ok = await checkSignature(cur, el.key.value, el.b64.checked);
      if (run !== verifyRun) return;
      setVerify(ok ? 'ok' : 'bad', ok ? 'Signature verified. The token was signed with this key and has not been changed.' : 'Invalid signature. The key does not match, or the token was changed.');
    } catch (e) {
      if (run !== verifyRun) return;
      setVerify('info', e instanceof UserError ? e.message : 'The signature could not be checked.');
    }
  }

  /* ---------- Sample ---------- */
  async function makeSample() {
    const now = Math.floor(Date.now() / 1000);
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = {
      iss: 'https://auth.example.com',
      sub: 'user_8142',
      aud: 'my-app',
      name: 'Amina Rauf',
      role: 'editor',
      scope: ['read', 'write'],
      iat: now,
      nbf: now,
      exp: now + 3600,
      jti: 'a7c1e5d2-90b4-4c3e-8f21-6d5b7e0c1a44'
    };
    const part = (o) => bytesToB64url(enc.encode(JSON.stringify(o)));
    const signingInput = part(header) + '.' + part(payload);
    try {
      const key = await crypto.subtle.importKey('raw', enc.encode(SAMPLE_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(signingInput)));
      return signingInput + '.' + bytesToB64url(sig);
    } catch (e) {
      return signingInput + '.' + bytesToB64url(enc.encode('sample-signature'));
    }
  }

  async function loadSample() {
    el.token.value = await makeSample();
    el.key.value = SAMPLE_SECRET;
    el.b64.checked = false;
    update();
  }

  /* ---------- Copy ---------- */
  function copyText(btn, text, node) {
    if (!text) return;
    const label = btn.textContent;
    const done = () => { btn.textContent = 'Copied'; setTimeout(() => { btn.textContent = label; }, 1500); };
    const fallback = () => {
      const r = document.createRange();
      r.selectNodeContents(node);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(r);
      btn.textContent = 'Press Ctrl/Cmd + C';
      setTimeout(() => { btn.textContent = label; }, 2500);
    };
    try { navigator.clipboard.writeText(text).then(done, fallback); } catch (e) { fallback(); }
  }

  /* ---------- Events ---------- */
  let timer = null;
  el.token.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(update, 150); });
  el.key.addEventListener('input', () => { clearTimeout(el.key._t); el.key._t = setTimeout(verify, 200); });
  el.b64.addEventListener('change', verify);
  el.btnSample.addEventListener('click', loadSample);
  el.btnClear.addEventListener('click', () => { el.token.value = ''; el.key.value = ''; update(); el.token.focus(); });
  el.copyHeader.addEventListener('click', () => copyText(el.copyHeader, headerText, el.headerOut));
  el.copyPayload.addEventListener('click', () => copyText(el.copyPayload, payloadText, el.payloadOut));

  /* ---------- Start ---------- */
  loadSample();
})();
