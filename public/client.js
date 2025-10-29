(() => {
  // helpers
  const logIncoming = (s) => { const el = document.getElementById('incoming'); el.innerHTML += `<p>${s}</p>`; el.scrollTop = el.scrollHeight; };
  const logOutgoing = (s) => { const el = document.getElementById('outgoing'); el.innerHTML += `<p>${s}</p>`; el.scrollTop = el.scrollHeight; };
  const logPeer = (s) => { const el = document.getElementById('peers'); el.innerHTML += `<p>${s}</p>`; el.scrollTop = el.scrollHeight; };
  const sys = (t) => { document.getElementById('system').textContent = t; };

  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const fromB64 = (s) => { const bin = atob(s); const buf = new Uint8Array(bin.length); for (let i=0;i<bin.length;i++) buf[i]=bin.charCodeAt(i); return buf.buffer; };

  // PEM helpers (SPKI / PKCS8)
  function arrayBufferToPem(buffer, type) {
    const b64str = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    const lines = b64str.match(/.{1,64}/g).join('\n');
    return `-----BEGIN ${type}-----\n${lines}\n-----END ${type}-----\n`;
  }
  function pemToArrayBuffer(pem) {
    const b64 = pem.replace(/-----(BEGIN|END)[\w\s]+-----/g, '').replace(/\s+/g,'');
    return fromB64(b64);
  }

  // convert SPKI/PKCS8 ArrayBuffer to CryptoKey imports
  async function importPublicKeyFromPem(pem) {
    const spki = pemToArrayBuffer(pem);
    return crypto.subtle.importKey('spki', spki, { name:'RSA-OAEP', hash:'SHA-256' }, true, ['encrypt','wrapKey']);
  }
  async function importPrivateKeyFromPem(pem) {
    const pkcs8 = pemToArrayBuffer(pem);
    return crypto.subtle.importKey('pkcs8', pkcs8, { name:'RSA-OAEP', hash:'SHA-256' }, true, ['decrypt','unwrapKey']);
  }

  // state
  let ws = null;
  let myUsername = null;
  let myKeyPair = null; // CryptoKeyPair
  let myPrivateKey = null; // CryptoKey for unwrapping
  const peersPublic = {}; // username -> PEM string OR CryptoKey

  // UI nodes
  const btnRegister = document.getElementById('btn-register');
  const btnGenKeys = document.getElementById('btn-gen-keys');
  const btnExportPub = document.getElementById('btn-export-pub');
  const btnSendPub = document.getElementById('btn-send-pub');
  const btnSendMsg = document.getElementById('btn-send-msg');
  const btnSendFile = document.getElementById('btn-send-file');

  // connect websocket
  function ensureWS() {
    if (ws && ws.readyState === WebSocket.OPEN) return;
    ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host);
    ws.onopen = () => sys('WebSocket connected');
    ws.onclose = () => sys('WebSocket disconnected');
    ws.onerror = (e) => sys('WebSocket error: ' + e.message);
    ws.onmessage = async (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        handleServerMessage(msg);
      } catch (e) {
        console.warn('bad msg', e);
      }
    };
  }

  // register
  btnRegister.addEventListener('click', () => {
    const username = document.getElementById('username').value.trim();
    if (!username) { alert('enter username'); return; }
    myUsername = username;
    ensureWS();
    ws.addEventListener('open', () => {
      ws.send(JSON.stringify({ type:'register', username }));
    }, { once: true });
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type:'register', username }));
    }
    sys('Registered as ' + username);
  });

  // generate RSA keypair (client side)
  btnGenKeys.addEventListener('click', async () => {
    btnGenKeys.disabled = true; sys('Generating RSA keypair...');
    try {
      myKeyPair = await crypto.subtle.generateKey(
        { name:'RSA-OAEP', modulusLength:2048, publicExponent: new Uint8Array([1,0,1]), hash:'SHA-256' },
        true,
        ['wrapKey','unwrapKey','encrypt','decrypt']
      );
      myPrivateKey = myKeyPair.privateKey;

      // export public key (SPKI) to PEM
      const spki = await crypto.subtle.exportKey('spki', myKeyPair.publicKey);
      const pem = arrayBufferToPem(spki, 'PUBLIC KEY');
      // store my public PEM so we can send it to peers
      myPublicPem = pem;
      btnExportPub.disabled = false;
      sys('RSA keypair ready. Click "Send my public key to peer" after entering peer username.');
    } catch (e) {
      console.error(e); alert('Key generation failed: ' + e);
    } finally {
      btnGenKeys.disabled = false;
    }
  });

  // export public PEM (download)
  btnExportPub.addEventListener('click', async () => {
    if (!myKeyPair) { alert('generate keys first'); return; }
    const spki = await crypto.subtle.exportKey('spki', myKeyPair.publicKey);
    const pem = arrayBufferToPem(spki, 'PUBLIC KEY');
    const blob = new Blob([pem], { type:'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `${myUsername || 'me'}_public.pem`; a.click();
    URL.revokeObjectURL(url);
  });

  // send my public key to a peer
  btnSendPub.addEventListener('click', async () => {
    const peer = document.getElementById('peer').value.trim();
    if (!peer) return alert('enter peer username');
    if (!myKeyPair) return alert('generate keys first');
    if (!myUsername) return alert('register first');

    // export and send PEM
    const spki = await crypto.subtle.exportKey('spki', myKeyPair.publicKey);
    const pem = arrayBufferToPem(spki, 'PUBLIC KEY');

    ensureWS();
    ws.send(JSON.stringify({ type:'publicKey', from: myUsername, to: peer, publicKey: pem }));
    sys(`Sent public key to ${peer}`);
    logOutgoing(`sent public key to ${peer}`);
  });

  // Handle messages from server
  async function handleServerMessage(msg) {
    if (msg.type === 'system') {
      sys(msg.message || JSON.stringify(msg));
      return;
    }
    if (msg.type === 'presence') {
      sys(`${msg.username} is online`);
      return;
    }
    if (msg.type === 'publicKey' && msg.from && msg.publicKey) {
      // store peer public PEM
      peersPublic[msg.from] = msg.publicKey;
      logPeer(`Received public key from ${msg.from}`);
      return;
    }
    if (msg.type === 'relay' && msg.from && msg.payload) {
      // payload: opaque JSON with kind:'text'|'file'
      const { payload } = msg;
      if (payload.kind === 'text') {
        // Contains wrappedKeyB64, ivB64, cipherB64
        try {
          const plain = await decryptRelayed(payload);
          logIncoming(`From ${msg.from}: ${plain}`);
        } catch (e) {
          logIncoming(`From ${msg.from}: (decrypt failed)`);
          console.error(e);
        }
      } else if (payload.kind === 'file') {
        try {
          const { filename, plainBuffer } = await decryptRelayedFile(payload);
          // create download link
          const blob = new Blob([plainBuffer]);
          const url = URL.createObjectURL(blob);
          logIncoming(`File from ${msg.from}: <a href="${url}" download="${filename}">Download ${filename}</a>`);
        } catch (e) {
          logIncoming(`File from ${msg.from}: (decrypt failed)`);
          console.error(e);
        }
      }
      return;
    }
  }

  // send encrypted text message
  btnSendMsg.addEventListener('click', async () => {
    if (!myUsername) return alert('register first');
    const peer = document.getElementById('peer').value.trim();
    if (!peer) return alert('enter peer username');
    if (!peersPublic[peer]) return alert('no public key for peer. Ask them to send their public key.');

    const plain = document.getElementById('msg').value;
    if (!plain) return alert('enter message');
    try {
      // 1. generate ephemeral AES-GCM key
      const aesKey = await crypto.subtle.generateKey({ name:'AES-GCM', length:256 }, true, ['encrypt','decrypt','wrapKey','unwrapKey']);

      // 2. encrypt plaintext
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const enc = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, aesKey, new TextEncoder().encode(plain));
      const cipherB64 = b64(enc);
      const ivB64 = b64(iv.buffer);

      // 3. import peer public key and wrap AES key
      const peerPubPem = peersPublic[peer];
      const peerPubKey = await importPublicKeyFromPem(peerPubPem);
      const wrapped = await crypto.subtle.wrapKey('raw', aesKey, peerPubKey, { name:'RSA-OAEP' });
      const wrappedKeyB64 = b64(wrapped);

      // 4. send opaque payload via server
      const payload = { kind:'text', cipherB64, ivB64, wrappedKeyB64 };
      ensureWS();
      ws.send(JSON.stringify({ type:'relay', from: myUsername, to: peer, payload }));

      logOutgoing(`To ${peer}: ${plain} (encrypted)`);
    } catch (e) {
      console.error(e); alert('send failed: ' + e);
    }
  });

  // send encrypted file
  btnSendFile.addEventListener('click', async () => {
    if (!myUsername) return alert('register first');
    const peer = document.getElementById('peer').value.trim();
    if (!peer) return alert('enter peer username');
    if (!peersPublic[peer]) return alert('no public key for peer. Ask them to send their public key.');

    const fileInput = document.getElementById('fileinput');
    if (!fileInput.files || !fileInput.files[0]) return alert('choose a file');
    const file = fileInput.files[0];

    try {
      const arrayBuffer = await file.arrayBuffer();

      // 1. generate ephemeral AES-GCM key
      const aesKey = await crypto.subtle.generateKey({ name:'AES-GCM', length:256 }, true, ['encrypt','decrypt','wrapKey','unwrapKey']);

      // 2. encrypt file bytes
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const enc = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, aesKey, arrayBuffer);
      const cipherB64 = b64(enc);
      const ivB64 = b64(iv.buffer);

      // 3. wrap AES with peer public key
      const peerPubPem = peersPublic[peer];
      const peerPubKey = await importPublicKeyFromPem(peerPubPem);
      const wrapped = await crypto.subtle.wrapKey('raw', aesKey, peerPubKey, { name:'RSA-OAEP' });
      const wrappedKeyB64 = b64(wrapped);

      // 4. send via relay
      const payload = { kind:'file', filename: file.name, cipherB64, ivB64, wrappedKeyB64 };
      ensureWS();
      ws.send(JSON.stringify({ type:'relay', from: myUsername, to: peer, payload }));

      logOutgoing(`File to ${peer}: ${file.name} (encrypted)`);
    } catch (e) {
      console.error(e); alert('file send failed: ' + e);
    }
  });

  // Decrypt relayed text payload (wrappedKeyB64, ivB64, cipherB64)
  async function decryptRelayed(payload) {
    if (!myPrivateKey) throw new Error('no private key to unwrap');
    const wrappedBuf = fromB64(payload.wrappedKeyB64);
    // unwrap AES key
    const aesKey = await crypto.subtle.unwrapKey('raw', wrappedBuf, myPrivateKey, { name:'RSA-OAEP' }, { name:'AES-GCM', length:256 }, true, ['decrypt']);
    const iv = fromB64(payload.ivB64);
    const cipherBuf = fromB64(payload.cipherB64);
    const plainBuf = await crypto.subtle.decrypt({ name:'AES-GCM', iv: new Uint8Array(iv) }, aesKey, cipherBuf);
    return new TextDecoder().decode(plainBuf);
  }

  // Decrypt relayed file payload
  async function decryptRelayedFile(payload) {
    if (!myPrivateKey) throw new Error('no private key to unwrap');
    const wrappedBuf = fromB64(payload.wrappedKeyB64);
    const aesKey = await crypto.subtle.unwrapKey('raw', wrappedBuf, myPrivateKey, { name:'RSA-OAEP' }, { name:'AES-GCM', length:256 }, true, ['decrypt']);
    const iv = fromB64(payload.ivB64);
    const cipherBuf = fromB64(payload.cipherB64);
    const plainBuf = await crypto.subtle.decrypt({ name:'AES-GCM', iv: new Uint8Array(iv) }, aesKey, cipherBuf);
    return { filename: payload.filename, plainBuffer: plainBuf };
  }

  // Allow user to paste/import private key PEM manually (quick demo convenience)
  // We'll add a simple prompt to paste private key PEM when the app receives a public key from someone:
  // In a production app you'd have a proper key storage UI or PKI
  // For the demo, we auto-prompt for private key when the first 'publicKey' for a peer is received, if we don't have a private key.
  // However, provide a direct way to paste private key via context menu:
  window.addEventListener('keydown', (e) => {
    // Ctrl+P -> paste private PEM
    if (e.ctrlKey && e.key === 'p') {
      const pem = prompt('Paste your PRIVATE KEY (PKCS8 PEM) now:');
      if (pem) {
        importPrivateKeyFromPem(pem).then(k => {
          myPrivateKey = k;
          sys('Private key imported (PEM). You can now decrypt messages.');
        }).catch(err => alert('import failed: ' + err));
      }
    }
  });

  // Also allow user to paste private key by clicking the "Generate RSA" button again:
  // If user pastes private PEM into prompt when clicking "Generate RSA" and we detect PEM, we import.
  // (A simple convenience — not sophisticated UI.)

  // Expose minimal instructions
  sys('Press Ctrl+P to paste your private key PEM for decryption. Generate keys to create a pair, or exchange PEM files out-of-band.');

  // ensure websocket created on first interaction
  ensureWS();
})();