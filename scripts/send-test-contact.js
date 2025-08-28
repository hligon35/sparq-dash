#!/usr/bin/env node
// Sends a test contact submission to the portal endpoint.
const https = require('https');
const { URL } = require('url');

const CONTACT_URL = process.env.PORTAL_CONTACT_URL || 'https://portal.getsparqd.com/api/contact';
const ORIGIN = process.env.TEST_ORIGIN || 'https://portal.getsparqd.com';
const SITE = process.env.TEST_SITE || 'melawholefoodsva.com';

const payload = {
  name: 'Contact Test Bot',
  email: 'no-reply@getsparqd.com',
  phone: '000-000-0000',
  subject: 'TEST: Mela Whole Foods contact routing',
  message: 'This is a test submission triggered by send-test-contact.js',
  site: SITE,
  hp: ''
};

const body = JSON.stringify(payload);
const u = new URL(CONTACT_URL);
const opts = {
  method: 'POST',
  hostname: u.hostname,
  path: u.pathname + u.search,
  headers: {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(body),
    'origin': ORIGIN,
    'user-agent': 'sparq-contact-test'
  }
};

const req = https.request(opts, (res) => {
  let data = '';
  res.on('data', (d) => (data += d));
  res.on('end', () => {
    const status = res.statusCode;
    try {
      const json = JSON.parse(data || '{}');
      console.log('STATUS', status);
      console.log('RESPONSE', json);
    } catch (_) {
      console.log('STATUS', status);
      console.log('RAW', data);
    }
  });
});
req.on('error', (e) => {
  console.error('REQUEST ERROR', e.message);
  process.exit(1);
});
req.write(body);
req.end();
