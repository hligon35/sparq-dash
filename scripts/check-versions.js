#!/usr/bin/env node
// Queries version/health endpoints across services and prints a compact table.
const https = require('https');
const http = require('http');

const services = [
  {
    name: 'portal',
    base: process.env.PORTAL_URL || 'https://portal.getsparqd.com',
    versionPath: '/api/version',
    healthPath: '/healthz',
  },
  {
    name: 'sparqplug',
    base: process.env.PLUG_URL || 'https://sparqplug.getsparqd.com',
    versionPath: '/api/version',
    healthPath: '/_app_health',
  },
  {
    name: 'landing',
    base: process.env.LANDING_URL || 'https://getsparqd.com',
    versionPath: '/version.json', // optional if published
    healthPath: '/', // treat root 200 as healthy
  },
];

function req(u) {
  return new Promise((resolve) => {
    const mod = u.startsWith('https') ? https : http;
    const url = new URL(u);
    const opts = { method: 'GET', hostname: url.hostname, path: url.pathname + url.search, headers: { 'user-agent': 'sparq-check' } };
    const r = mod.request(opts, (res) => {
      let body = '';
      res.on('data', (d) => (body += d));
      res.on('end', () => resolve({ status: res.statusCode || 0, body }));
    });
    r.on('error', () => resolve({ status: 0, body: '' }));
    r.end();
  });
}

async function main() {
  const rows = [];
  for (const s of services) {
    let version = null;
    let ok = false;
    let commit = null;
    let time = null;
    try {
      const v = await req(s.base.replace(/\/$/, '') + (s.versionPath || '/api/version'));
      if (v.status === 200) {
        const j = JSON.parse(v.body);
        version = j.version;
        commit = j?.build?.commit || null;
        time = j?.build?.time || null;
      }
    } catch (_) {}
    try {
      const h = await req(s.base.replace(/\/$/, '') + (s.healthPath || '/healthz'));
      ok = h.status === 200;
    } catch (_) {}
    rows.push({ name: s.name, ok, version, commit, time });
  }
  const out = rows
    .map((r) => `${r.name.padEnd(9)} | ${r.ok ? 'OK ' : 'BAD'} | v=${r.version || '-'} | commit=${r.commit || '-'} | time=${r.time || '-'}`)
    .join('\n');
  console.log(out);
}

main().catch((e) => {
  console.error('check failed', e);
  process.exit(1);
});
