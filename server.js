// server.js
const express = require('express');
const path = require('path');
const WebSocket = require('ws');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (_, res) => res.sendFile(path.join(__dirname, 'public/index.html')));

const server = app.listen(PORT, () => {
  console.log(`HTTP server listening on http://localhost:${PORT}`);
});

// WebSocket server (blind relay)
const wss = new WebSocket.Server({ server });

/**
 * We keep a map of username -> ws connection so clients can address messages to specific user.
 * Protocol: JSON messages with a 'type' field:
 * - register: { type: 'register', username, publicKey }  // publicKey optional
 * - publicKey: { type:'publicKey', from, to, publicKey }  // relay public key to specific peer
 * - relay: { type: 'relay', from, to, payload } // payload is any opaque object (encrypted data)
 */

const clients = new Map();

wss.on('connection', (ws) => {
  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch (e) {
      console.warn('non-json message ignored');
      return;
    }

    // Register a username
    if (msg.type === 'register' && msg.username) {
      // if someone else already had this username, close it
      const prev = clients.get(msg.username);
      if (prev && prev.readyState === WebSocket.OPEN) {
        prev.send(JSON.stringify({ type: 'system', message: 'You were logged out because someone else registered the same username.' }));
        prev.close();
      }
      clients.set(msg.username, ws);
      ws.username = msg.username;
      console.log(`Registered user: ${msg.username}`);
      // Optionally forward the publicKey to others if included
      if (msg.publicKey) {
        // broadcast announcement
        broadcast(JSON.stringify({ type: 'presence', username: msg.username }), ws);
      }
      return;
    }

    // Forward publicKey to a specific recipient
    if (msg.type === 'publicKey' && msg.to && msg.publicKey && msg.from) {
      const target = clients.get(msg.to);
      if (target && target.readyState === WebSocket.OPEN) {
        target.send(JSON.stringify({ type: 'publicKey', from: msg.from, publicKey: msg.publicKey }));
      } else {
        // notify sender that target not available
        const sender = clients.get(msg.from);
        if (sender && sender.readyState === WebSocket.OPEN) {
          sender.send(JSON.stringify({ type: 'system', message: `User ${msg.to} not connected` }));
        }
      }
      return;
    }

    // Relay opaque payload to recipient
    if (msg.type === 'relay' && msg.to && msg.from && msg.payload) {
      const target = clients.get(msg.to);
      if (target && target.readyState === WebSocket.OPEN) {
        target.send(JSON.stringify({ type: 'relay', from: msg.from, payload: msg.payload }));
      } else {
        // reply back to sender with error
        const sender = clients.get(msg.from);
        if (sender && sender.readyState === WebSocket.OPEN) {
          sender.send(JSON.stringify({ type: 'system', message: `User ${msg.to} not connected` }));
        }
      }
      return;
    }

    // Generic: if message has 'to' and 'from', try to forward
    if (msg.to && msg.from) {
      const t = clients.get(msg.to);
      if (t && t.readyState === WebSocket.OPEN) {
        t.send(JSON.stringify(msg));
      }
      return;
    }

    // fallback: broadcast
    broadcast(JSON.stringify(msg), ws);
  });

  ws.on('close', () => {
    if (ws.username) {
      clients.delete(ws.username);
      broadcast(JSON.stringify({ type: 'presence-off', username: ws.username }), ws);
    }
  });
});

// Helper to broadcast to all except optional skipWs
function broadcast(data, skipWs) {
  wss.clients.forEach((c) => {
    if (c !== skipWs && c.readyState === WebSocket.OPEN) c.send(data);
  });
}