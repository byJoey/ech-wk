const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CF_FALLBACK_IPS = ['ProxyIP.CMLiussss.net'];// cm维护

// ---------------------------------------------------------------------------
// Optional VLESS/XHTTP endpoint (disabled unless UUID is configured).
// The existing SOCKS5/HTTP-over-WebSocket tunnel below is untouched.
// Prefer env.UUID; XHTTP_UUID is a fallback for single-file deployments.
// ---------------------------------------------------------------------------
const XHTTP_UUID = '';
const XHTTP_PATH = '';
const XHTTP_PADDING_HEADER = 'X-Request-Id';
const XHTTP_PADDING_KEY = 'request_id';
const XHTTP_PADDING_FROM = 32;
const XHTTP_PADDING_TO = 64;
const XHTTP_PADDING_TOLERANCE = 2;
// HPACK static Huffman code lengths (RFC 7541, Appendix B), indexed by octet.
const HPACK_CODE_LENGTHS = [
  13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
  28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
  6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
  5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
  13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
  7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
  15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
  6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
  20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
  24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
  22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
  21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
  26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
  19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
  20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
  26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
  30
];

// 复用 TextEncoder，避免重复创建
const encoder = new TextEncoder();
const decoder = new TextDecoder();

import { connect } from 'cloudflare:sockets';

export default {
  async fetch(request, env, ctx) {
    try {
      const xhttpUuid = normalizeUuid((env && (env.UUID || env.uuid)) || XHTTP_UUID);
      if (xhttpUuid && request.method === 'POST') {
        const path = new URL(request.url).pathname;
        if (!isXhttpPath(path, xhttpUuid, (env && (env.XHTTP_PATH || env.xhttp_path)) || XHTTP_PATH)) {
          return new Response('Not Found', { status: 404 });
        }
        try {
          return await handleXhttp(request, xhttpUuid, ctx);
        } catch (err) {
          console.error('[xhttp] unhandled error', err && err.stack || err);
          return new Response('Internal Server Error', { status: 500 });
        }
      }

      const token = '';
      const upgradeHeader = request.headers.get('Upgrade');
      
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
        return new URL(request.url).pathname === '/' 
          ? new Response('WebSocket Proxy Server', { status: 200 })
          : new Response('Expected WebSocket', { status: 426 });
      }

      if (token && request.headers.get('Sec-WebSocket-Protocol') !== token) {
        return new Response('Unauthorized', { status: 401 });
      }

      const [client, server] = Object.values(new WebSocketPair());
      server.accept();
      
      handleSession(server).catch(() => safeCloseWebSocket(server));

      // 修复 spread 类型错误
      const responseInit = {
        status: 101,
        webSocket: client
      };
      
      if (token) {
        responseInit.headers = { 'Sec-WebSocket-Protocol': token };
      }

      return new Response(null, responseInit);
      
    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  },
};

async function handleSession(webSocket) {
  let remoteSocket, remoteWriter, remoteReader;
  let isClosed = false;

  const cleanup = () => {
    if (isClosed) return;
    isClosed = true;
    
    try { remoteWriter?.releaseLock(); } catch {}
    try { remoteReader?.releaseLock(); } catch {}
    try { remoteSocket?.close(); } catch {}
    
    remoteWriter = remoteReader = remoteSocket = null;
    safeCloseWebSocket(webSocket);
  };

  const pumpRemoteToWebSocket = async () => {
    try {
      while (!isClosed && remoteReader) {
        const { done, value } = await remoteReader.read();
        
        if (done) break;
        if (webSocket.readyState !== WS_READY_STATE_OPEN) break;
        if (value?.byteLength > 0) webSocket.send(value);
      }
    } catch {}
    
    if (!isClosed) {
      try { webSocket.send('CLOSE'); } catch {}
      cleanup();
    }
  };

  const parseAddress = (addr) => {
    if (addr[0] === '[') {
      const end = addr.indexOf(']');
      return {
        host: addr.substring(1, end),
        port: parseInt(addr.substring(end + 2), 10)
      };
    }
    const sep = addr.lastIndexOf(':');
    return {
      host: addr.substring(0, sep),
      port: parseInt(addr.substring(sep + 1), 10)
    };
  };

  const isCFError = (err) => {
    const msg = err?.message?.toLowerCase() || '';
    return msg.includes('proxy request') || 
           msg.includes('cannot connect') || 
           msg.includes('cloudflare');
  };

  const connectToRemote = async (targetAddr, firstFrameData) => {
    const { host, port } = parseAddress(targetAddr);
    const attempts = [null, ...CF_FALLBACK_IPS];

    for (let i = 0; i < attempts.length; i++) {
      try {
        remoteSocket = connect({
          hostname: attempts[i] || host,
          port
        });

        if (remoteSocket.opened) await remoteSocket.opened;

        remoteWriter = remoteSocket.writable.getWriter();
        remoteReader = remoteSocket.readable.getReader();

        // 发送首帧数据
        if (firstFrameData) {
          await remoteWriter.write(encoder.encode(firstFrameData));
        }

        webSocket.send('CONNECTED');
        pumpRemoteToWebSocket();
        return;

      } catch (err) {
        // 清理失败的连接
        try { remoteWriter?.releaseLock(); } catch {}
        try { remoteReader?.releaseLock(); } catch {}
        try { remoteSocket?.close(); } catch {}
        remoteWriter = remoteReader = remoteSocket = null;

        // 如果不是 CF 错误或已是最后尝试，抛出错误
        if (!isCFError(err) || i === attempts.length - 1) {
          throw err;
        }
      }
    }
  };

  webSocket.addEventListener('message', async (event) => {
    if (isClosed) return;

    try {
      const data = event.data;

      if (typeof data === 'string') {
        if (data.startsWith('CONNECT:')) {
          const sep = data.indexOf('|', 8);
          await connectToRemote(
            data.substring(8, sep),
            data.substring(sep + 1)
          );
        }
        else if (data.startsWith('DATA:')) {
          if (remoteWriter) {
            await remoteWriter.write(encoder.encode(data.substring(5)));
          }
        }
        else if (data === 'CLOSE') {
          cleanup();
        }
      }
      else if (data instanceof ArrayBuffer && remoteWriter) {
        await remoteWriter.write(new Uint8Array(data));
      }
    } catch (err) {
      try { webSocket.send('ERROR:' + err.message); } catch {}
      cleanup();
    }
  });

  webSocket.addEventListener('close', cleanup);
  webSocket.addEventListener('error', cleanup);
}

function safeCloseWebSocket(ws) {
  try {
    if (ws.readyState === WS_READY_STATE_OPEN || 
        ws.readyState === WS_READY_STATE_CLOSING) {
      ws.close(1000, 'Server closed');
    }
  } catch {}
}

// ---------------------------------------------------------------------------
// VLESS over XHTTP (stream-one)
// ---------------------------------------------------------------------------

function normalizeUuid(value) {
  if (typeof value !== 'string') return '';
  const compact = value.trim().toLowerCase().replace(/-/g, '');
  return /^[0-9a-f]{32}$/.test(compact) ? compact : '';
}

function isXhttpPath(path, compactUuid, customPath) {
  const bases = ['/' + compactUuid, '/' + compactUuid.slice(0, 8)];
  if (customPath && String(customPath).trim()) {
    let base = String(customPath).trim();
    if (!base.startsWith('/')) base = '/' + base;
    base = base.replace(/\/+$/, '');
    if (base) bases.push(base);
  }
  return bases.some(base => path === base || path.startsWith(base + '/'));
}

function concatBytes(left, right) {
  if (!left.length) return right;
  if (!right.length) return left;
  const out = new Uint8Array(left.length + right.length);
  out.set(left, 0);
  out.set(right, left.length);
  return out;
}

function bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

function parseVlessHeader(buffer) {
  if (buffer.length < 18) return { needMore: true };
  if (buffer[0] !== 0) return { error: 'unsupported VLESS version' };

  const uuid = bytesToHex(buffer.subarray(1, 17));
  const addonLength = buffer[17];
  let offset = 18 + addonLength;
  if (buffer.length < offset + 3) return { needMore: true };

  const command = buffer[offset++];
  const port = (buffer[offset] << 8) | buffer[offset + 1];
  offset += 2;
  if (buffer.length < offset + 1) return { needMore: true };

  const addressType = buffer[offset++];
  let host = '';
  if (addressType === 1) {
    if (buffer.length < offset + 4) return { needMore: true };
    host = `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
    offset += 4;
  } else if (addressType === 2) {
    if (buffer.length < offset + 1) return { needMore: true };
    const length = buffer[offset++];
    if (buffer.length < offset + length) return { needMore: true };
    host = decoder.decode(buffer.subarray(offset, offset + length));
    offset += length;
  } else if (addressType === 3) {
    if (buffer.length < offset + 16) return { needMore: true };
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(((buffer[offset + i] << 8) | buffer[offset + i + 1]).toString(16));
    }
    host = parts.join(':');
    offset += 16;
  } else {
    return { error: 'unsupported address type' };
  }

  if (!host || !port) return { error: 'invalid target' };
  return { ok: true, uuid, command, host, port, offset };
}

function getXhttpPadding(request) {
  const headerValue = request.headers.get(XHTTP_PADDING_HEADER);
  if (headerValue) {
    try {
      const parsed = new URL(headerValue, 'https://x.invalid');
      const queryValue = parsed.searchParams.get(XHTTP_PADDING_KEY);
      if (queryValue) return queryValue;
    } catch (err) {}
    return headerValue;
  }
  try {
    return new URL(request.url).searchParams.get(XHTTP_PADDING_KEY) || '';
  } catch (err) {
    return '';
  }
}

function huffmanLength(value) {
  const bytes = encoder.encode(value);
  let bits = 0;
  for (let i = 0; i < bytes.length; i++) bits += HPACK_CODE_LENGTHS[bytes[i]];
  return Math.ceil(bits / 8);
}

function isValidTokenishPadding(value) {
  if (!value || value.length < 16 || value.length > 512) return false;
  if (!/^[0-9A-Za-z]+$/.test(value)) return false;
  // repeat-x padding is a single repeated character; tokenish is random base62.
  if (new Set(value).size < 4) return false;
  const length = huffmanLength(value);
  return length >= XHTTP_PADDING_FROM - XHTTP_PADDING_TOLERANCE &&
         length <= XHTTP_PADDING_TO + XHTTP_PADDING_TOLERANCE;
}

function randomBase62(length) {
  const charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let value = '';
  for (let i = 0; i < length; i++) value += charset[bytes[i] % charset.length];
  return value;
}

function generateTokenishPadding() {
  const target = XHTTP_PADDING_FROM +
    Math.floor(Math.random() * (XHTTP_PADDING_TO - XHTTP_PADDING_FROM + 1));
  let value = randomBase62(Math.ceil(target / 0.8));
  let adjust = 'X';
  for (let i = 0; i < 150; i++) {
    const current = huffmanLength(value);
    const diff = current - target;
    if (Math.abs(diff) <= XHTTP_PADDING_TOLERANCE) break;
    if (diff < 0) {
      value += adjust;
      adjust = adjust === 'X' ? 'Z' : 'X';
    } else {
      value = value.slice(0, -1);
      if (!value) value = 'X';
    }
  }
  if (new Set(value).size < 4) return generateTokenishPadding();
  return value;
}

async function handleXhttp(request, compactUuid, ctx) {
  const padding = getXhttpPadding(request);
  if (!isValidTokenishPadding(padding)) {
    return new Response('Invalid X-Request-Id padding', { status: 400 });
  }
  if (!request.body) return new Response('Bad Request', { status: 400 });

  let responseSocket = null;
  const stream = new TransformStream({
    transform(chunk, controller) {
      controller.enqueue(chunk);
    },
    cancel() {
      try { responseSocket && responseSocket.close(); } catch (err) {}
    }
  }, null, new ByteLengthQueuingStrategy({ highWaterMark: 128 * 1024 }));

  const writer = stream.writable.getWriter();
  (async () => {
    let reader = null;
    try {
      reader = request.body.getReader();
      let buffer = new Uint8Array(0);
      let parsed = null;
      while (buffer.length < 2048) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value && value.byteLength) buffer = concatBytes(buffer, value);
        parsed = parseVlessHeader(buffer);
        if (parsed.ok || parsed.error) break;
      }
      if (!parsed || !parsed.ok) throw new Error('invalid VLESS header');
      if (parsed.uuid !== compactUuid) throw new Error('invalid UUID');
      if (parsed.command !== 1) throw new Error('unsupported command');

      responseSocket = connect({ hostname: parsed.host, port: parsed.port });
      if (responseSocket.opened) await responseSocket.opened;
      const uploadWriter = responseSocket.writable.getWriter();
      const downloadReader = responseSocket.readable.getReader();

      await writer.write(new Uint8Array([0, 0]));
      if (buffer.length > parsed.offset) {
        await uploadWriter.write(buffer.subarray(parsed.offset));
      }

      const upload = (async () => {
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            if (value && value.byteLength) await uploadWriter.write(value);
          }
        } catch (err) {
          try { responseSocket.close(); } catch (closeError) {}
        } finally {
          try { reader.releaseLock(); } catch (err) {}
        }
      })();

      try {
        while (true) {
          const { done, value } = await downloadReader.read();
          if (done) break;
          if (value && value.byteLength) await writer.write(value);
        }
      } finally {
        try { downloadReader.releaseLock(); } catch (err) {}
        try { responseSocket.close(); } catch (err) {}
        await Promise.allSettled([upload]);
      }
      await writer.close();
    } catch (err) {
      try { await writer.abort(err); } catch (abortError) {}
      try { if (reader) reader.releaseLock(); } catch (lockError) {}
    }
  })();

  return new Response(stream.readable, {
    status: 200,
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-Accel-Buffering': 'no',
      'Cache-Control': 'no-store',
      [XHTTP_PADDING_HEADER]: generateTokenishPadding()
    }
  });
}
