#!/usr/bin/env node
const http = require('http');

const HOST = process.env.HOST || 'localhost';
const PORT = process.env.PORT || 3003;
const USER = process.env.SMOKE_USER || 'hligon';
const PASS = process.env.SMOKE_PASS || process.env.DEFAULT_ADMIN_PASSWORD || 'sparqd2025!';

function req(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : undefined;
    const options = {
      hostname: HOST,
      port: PORT,
      path,
      method,
      headers: data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}
    };
    const r = http.request(options, (res) => {
      let buf = '';
      res.on('data', (c) => (buf += c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: buf }));
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

(async () => {
  try {
    const h = await req('GET', '/healthz');
    console.log('Health:', h.status, h.body);
  } catch (e) {
    console.error('Health check failed:', e.message);
    process.exitCode = 1;
    return;
  }
  try {
    const login = await req('POST', '/api/auth/login', { username: USER, password: PASS });
    console.log('Login status:', login.status);
    console.log('Login body:', login.body);
  } catch (e) {
    console.error('Login failed:', e.message);
    process.exitCode = 1;
  }
})();
