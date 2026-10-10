const net = require('net');
const tls = require('tls');
const { URL } = require('url');

const TIMEOUT_MS = 12000;

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ ok: false, error: 'Method not allowed' });

  const { host, port, username, password, target } = req.body || {};

  if (!host || !port) {
    return res.status(400).json({ ok: false, error: 'Host dan port wajib diisi' });
  }

  let targetUrl;
  try {
    targetUrl = new URL(target || 'https://api.ipify.org');
  } catch {
    return res.status(400).json({ ok: false, error: 'Target URL tidak valid' });
  }

  const result = await testHttpProxy({
    proxyHost: host,
    proxyPort: parseInt(port, 10),
    proxyUser: username || '',
    proxyPass: password || '',
    targetHost: targetUrl.hostname,
    targetPort: targetUrl.port ? parseInt(targetUrl.port, 10) : (targetUrl.protocol === 'https:' ? 443 : 80),
    targetPath: targetUrl.pathname + targetUrl.search,
    isHttps: targetUrl.protocol === 'https:',
  });

  return res.status(200).json(result);
};

function testHttpProxy({ proxyHost, proxyPort, proxyUser, proxyPass, targetHost, targetPort, targetPath, isHttps }) {
  return new Promise((resolve) => {
    const start = Date.now();
    let done = false;
    const finish = (r) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      r.latency = Date.now() - start;
      resolve(r);
    };

    const timer = setTimeout(() => {
      try { socket.destroy(); } catch {}
      finish({ ok: false, error: 'Timeout (12s) — proxy mungkin lambat atau tidak menjawab' });
    }, TIMEOUT_MS);

    const socket = net.connect(proxyPort, proxyHost);
    socket.setTimeout(TIMEOUT_MS);

    socket.on('error', (e) => finish({ ok: false, error: 'Connect error: ' + e.message }));
    socket.on('timeout', () => {
      try { socket.destroy(); } catch {}
      finish({ ok: false, error: 'Socket timeout' });
    });

    socket.on('connect', () => {
      const authHeader = proxyUser
        ? `Proxy-Authorization: Basic ${Buffer.from(`${proxyUser}:${proxyPass}`).toString('base64')}\r\n`
        : '';

      if (isHttps) {
        socket.write(
          `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n` +
          `Host: ${targetHost}:${targetPort}\r\n` +
          authHeader +
          `User-Agent: Mozilla/5.0\r\n\r\n`
        );
      } else {
        socket.write(
          `GET ${targetPath} HTTP/1.1\r\n` +
          `Host: ${targetHost}\r\n` +
          authHeader +
          `User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`
        );
      }
    });

    let headerBuf = Buffer.alloc(0);
    const onHeaderData = (chunk) => {
      headerBuf = Buffer.concat([headerBuf, chunk]);
      const headerEnd = headerBuf.indexOf('\r\n\r\n');
      if (headerEnd === -1) {
        if (headerBuf.length > 16384) {
          try { socket.destroy(); } catch {}
          finish({ ok: false, error: 'Response terlalu besar / bukan proxy' });
        }
        return;
      }

      const header = headerBuf.slice(0, headerEnd).toString();
      const statusMatch = header.match(/HTTP\/\d\.\d\s+(\d+)/);
      const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;

      if (status !== 200) {
        try { socket.destroy(); } catch {}
        return finish({ ok: false, error: `Proxy menolak (HTTP ${status || 'unknown'})` });
      }

      socket.removeListener('data', onHeaderData);

      if (!isHttps) {
        let body = headerBuf.slice(headerEnd + 4).toString();
        socket.on('data', (c) => { body += c.toString(); });
        socket.on('end', () => {
          const content = body.split('\r\n\r\n').pop().trim();
          finish({ ok: true, exitIp: extractIp(content), raw: content.slice(0, 200) });
        });
        return;
      }

      const tlsSocket = tls.connect(
        { socket, servername: targetHost, rejectUnauthorized: false },
        () => {
          tlsSocket.write(
            `GET ${targetPath} HTTP/1.1\r\nHost: ${targetHost}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`
          );
        }
      );

      let body = '';
      tlsSocket.on('data', (c) => { body += c.toString(); });
      tlsSocket.on('end', () => {
        const idx = body.indexOf('\r\n\r\n');
        const content = (idx >= 0 ? body.slice(idx + 4) : body).trim();
        finish({ ok: true, exitIp: extractIp(content), raw: content.slice(0, 200) });
      });
      tlsSocket.on('error', (e) => finish({ ok: false, error: 'TLS error: ' + e.message }));
    };

    socket.on('data', onHeaderData);
  });
}

function extractIp(text) {
  const m = text.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
  return m ? m[0] : null;
}
