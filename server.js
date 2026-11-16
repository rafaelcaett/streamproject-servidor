// Servidor de sinalizacao do StreamProject.
//
// Ele NAO transporta video: so apresenta quem transmite a quem assiste para
// que os dois fechem uma conexao direta (WebRTC). Tambem serve a pagina de
// quem assiste (pasta public/), se ela existir.
//
// O video continua mesmo que este servidor caia: quando ele volta, quem
// transmite reassume a sala (com o "token" que so ele conhece) e quem assiste
// retoma o proprio lugar (com o id que ja tinha), sem refazer a conexao.
//
// Variaveis de ambiente:
//   PORT           porta HTTP/WebSocket (padrao 8080)
//   HOST_KEY       se definida, so quem informar essa chave pode transmitir
//   MAX_VIEWERS    maximo de pessoas assistindo por sala (padrao 6)
//   HOST_GRACE_MS  tempo que a sala espera quem transmite voltar (padrao 45000)
//   ICE_SERVERS    JSON com servidores STUN/TURN, ex.:
//                  [{"urls":"stun:stun.l.google.com:19302"},
//                   {"urls":"turn:meu.turn:3478","username":"u","credential":"s"}]

'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PROTOCOL_VERSION = 2;
const PORT = Number(process.env.PORT) || 8080;
const HOST_KEY = process.env.HOST_KEY || '';
const MAX_VIEWERS = Number(process.env.MAX_VIEWERS) || 6;
const HOST_GRACE_MS = Number(process.env.HOST_GRACE_MS) || 45000;
const PUBLIC_DIR = path.join(__dirname, 'public');

let ICE_SERVERS = [
  { urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] },
  { urls: 'stun:stun.cloudflare.com:3478' },
];
if (process.env.ICE_SERVERS) {
  try {
    ICE_SERVERS = JSON.parse(process.env.ICE_SERVERS);
  } catch (err) {
    console.error('ICE_SERVERS invalido, usando o padrao:', err.message);
  }
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

// ---------- HTTP: saude e pagina de quem assiste ----------

const server = http.createServer((req, res) => {
  let pathname;
  try {
    pathname = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  } catch {
    res.writeHead(400).end();
    return;
  }

  if (pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify({ ok: true, v: PROTOCOL_VERSION, rooms: rooms.size }));
    return;
  }

  if (pathname === '/') pathname = '/index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, pathname));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) {
    res.writeHead(403).end();
    return;
  }

  fs.readFile(file, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Nao encontrado');
      return;
    }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file)] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
      'X-Content-Type-Options': 'nosniff',
    });
    res.end(data);
  });
});

// ---------- WebSocket: salas ----------

/**
 * host       conexao de quem transmite (null enquanto ele esta reconectando)
 * token      segredo de quem criou a sala; so com ele da para reassumi-la
 * viewers    id -> conexao de quem assiste
 * graceTimer contagem para encerrar a sala se quem transmite nao voltar
 */
const rooms = new Map();

const wss = new WebSocketServer({ server, maxPayload: 256 * 1024 });

function send(ws, msg) {
  if (ws && ws.readyState === ws.OPEN) ws.send(JSON.stringify(msg));
}

function sameSecret(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function normalizeRoom(value) {
  const room = String(value || '').trim().toLowerCase();
  return /^[a-z0-9_-]{3,32}$/.test(room) ? room : null;
}

function cleanName(value) {
  return String(value || '').replace(/[\u0000-\u001f]/g, '').trim().slice(0, 24) || 'Convidado';
}

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.role = null;
  ws.room = null;
  ws.viewerId = null;
  ws.viewerName = '';
  ws.failures = 0;

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return;
    }
    if (!msg || typeof msg.type !== 'string') return;

    switch (msg.type) {
      case 'host': return onHost(ws, msg);
      case 'join': return onJoin(ws, msg);
      case 'signal': return onSignal(ws, msg);
      case 'kick': return onKick(ws, msg);
      case 'end': return onEnd(ws);
    }
  });

  ws.on('close', () => onClose(ws));
  ws.on('error', () => {});
});

// "soft": recusas normais (sala ainda nao aberta) nao contam como tentativa suspeita.
function reject(ws, code, message, soft) {
  if (!soft) ws.failures += 1;
  // Pequeno atraso para desencorajar tentativa e erro de senha.
  setTimeout(() => {
    send(ws, { type: 'error', code, message });
    if (ws.failures >= 8) ws.close();
  }, 600);
}

function onHost(ws, msg) {
  if (ws.role) return;
  if (HOST_KEY && !sameSecret(msg.hostKey || '', HOST_KEY)) {
    return reject(ws, 'bad-host-key', 'Chave do servidor incorreta.');
  }
  const room = normalizeRoom(msg.room);
  if (!room) {
    return reject(ws, 'bad-room', 'Nome de sala invalido (use 3 a 32 letras, numeros, - ou _).');
  }

  const token = typeof msg.token === 'string' ? msg.token.slice(0, 128) : '';
  let entry = rooms.get(room);
  let resumed = false;

  if (entry) {
    // So quem criou a sala (mesmo token) pode reassumi-la.
    if (!token || !entry.token || !sameSecret(token, entry.token)) {
      return reject(ws, 'room-taken', 'Ja existe uma transmissao nessa sala.');
    }
    clearTimeout(entry.graceTimer);
    entry.graceTimer = null;
    const old = entry.host;
    if (old && old !== ws) {
      old.room = null;
      old.close();
    }
    entry.host = ws;
    entry.password = String(msg.password || '');
    resumed = true;
  } else {
    entry = { host: ws, token, password: String(msg.password || ''), viewers: new Map(), graceTimer: null };
    rooms.set(room, entry);
  }

  ws.role = 'host';
  ws.room = room;
  send(ws, {
    type: 'hosted',
    room,
    resumed,
    v: PROTOCOL_VERSION,
    iceServers: ICE_SERVERS,
    maxViewers: MAX_VIEWERS,
    viewers: [...entry.viewers].map(([id, viewer]) => ({ id, name: viewer.viewerName })),
  });
  console.log(`[sala ${room}] transmissao ${resumed ? 'retomada' : 'iniciada'}`);
}

function onJoin(ws, msg) {
  if (ws.role) return;
  const room = normalizeRoom(msg.room);
  const entry = room && rooms.get(room);
  if (!entry) {
    return reject(ws, 'no-room', 'Ninguem esta transmitindo nessa sala agora.', true);
  }
  if (entry.password && !sameSecret(msg.password || '', entry.password)) {
    return reject(ws, 'bad-password', 'Senha incorreta.');
  }

  // Quem ja estava assistindo volta com o mesmo id e mantem a conexao de video.
  const wanted = typeof msg.resume === 'string' && /^[a-f0-9]{12}$/.test(msg.resume) ? msg.resume : null;
  const previous = wanted ? entry.viewers.get(wanted) : null;
  if (!previous && entry.viewers.size >= MAX_VIEWERS) {
    return reject(ws, 'room-full', 'A sala esta cheia.');
  }
  if (previous && previous !== ws) {
    previous.room = null;
    previous.close();
  }

  const id = wanted || crypto.randomBytes(6).toString('hex');
  const name = cleanName(msg.name);
  ws.role = 'viewer';
  ws.room = room;
  ws.viewerId = id;
  ws.viewerName = name;
  entry.viewers.set(id, ws);

  send(ws, { type: 'joined', id, room, resumed: Boolean(wanted), v: PROTOCOL_VERSION, iceServers: ICE_SERVERS });
  send(entry.host, { type: 'viewer-joined', id, name, resumed: Boolean(wanted) });
  console.log(`[sala ${room}] ${name} ${wanted ? 'voltou' : 'entrou'} (${entry.viewers.size} assistindo)`);
}

function onSignal(ws, msg) {
  const entry = ws.room && rooms.get(ws.room);
  if (!entry || msg.data === undefined) return;

  if (ws.role === 'host') {
    const viewer = entry.viewers.get(String(msg.to));
    if (viewer) send(viewer, { type: 'signal', data: msg.data });
  } else if (ws.role === 'viewer' && entry.viewers.get(ws.viewerId) === ws) {
    send(entry.host, { type: 'signal', from: ws.viewerId, data: msg.data });
  }
}

function onKick(ws, msg) {
  const entry = ws.room && rooms.get(ws.room);
  if (!entry || ws.role !== 'host' || entry.host !== ws) return;
  const viewer = entry.viewers.get(String(msg.id));
  if (viewer) {
    send(viewer, { type: 'error', code: 'kicked', message: 'Voce foi removido da sala.' });
    viewer.close();
  }
}

// Quem transmite avisou que parou de proposito: encerra a sala na hora.
function onEnd(ws) {
  const room = ws.room;
  const entry = room && rooms.get(room);
  if (!entry || ws.role !== 'host' || entry.host !== ws) return;
  ws.room = null;
  endRoom(room);
}

function endRoom(room) {
  const entry = rooms.get(room);
  if (!entry) return;
  clearTimeout(entry.graceTimer);
  rooms.delete(room);
  for (const viewer of entry.viewers.values()) {
    send(viewer, { type: 'host-left' });
    viewer.room = null;
    viewer.close();
  }
  console.log(`[sala ${room}] transmissao encerrada`);
}

function onClose(ws) {
  const room = ws.room;
  const entry = room && rooms.get(room);
  if (!entry) return;

  if (ws.role === 'host' && entry.host === ws) {
    entry.host = null;
    if (entry.token) {
      // Pode ter sido so uma queda de conexao: o video segue direto entre os
      // PCs, entao a sala espera um pouco quem transmite voltar.
      clearTimeout(entry.graceTimer);
      entry.graceTimer = setTimeout(() => endRoom(room), HOST_GRACE_MS);
      console.log(`[sala ${room}] quem transmite caiu; aguardando voltar`);
    } else {
      endRoom(room);
    }
  } else if (ws.role === 'viewer' && entry.viewers.get(ws.viewerId) === ws) {
    entry.viewers.delete(ws.viewerId);
    send(entry.host, { type: 'viewer-left', id: ws.viewerId });
    console.log(`[sala ${room}] ${ws.viewerName} saiu (${entry.viewers.size} assistindo)`);
  }
}

// Mantem as conexoes vivas atras de proxies e derruba as que morreram.
const heartbeat = setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) {
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    ws.ping();
  }
}, 25000);

wss.on('close', () => clearInterval(heartbeat));

server.listen(PORT, () => {
  console.log(`StreamProject: servidor v${PROTOCOL_VERSION} no ar em http://localhost:${PORT}`);
  if (HOST_KEY) console.log('Chave de servidor exigida para transmitir.');
});
