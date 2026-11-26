'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { serve, call } = require('../../src/core/http.cjs');

const listen = (server) => new Promise((resolve) => server.once('listening', resolve));
const close = (server) => new Promise((resolve, reject) => server.close((e) => e ? reject(e) : resolve()));

test('serve binds loopback and call sends/receives JSON', async () => {
  const server = serve(0, new Map([['POST /echo', async (body) => ({ status: 200, json: { body } })]]));
  try {
    await listen(server);
    const address = server.address();
    assert.equal(address.address, '127.0.0.1');
    const response = await call(`http://127.0.0.1:${address.port}/echo`, 'POST', { hello: 'world' });
    assert.deepEqual(response, { status: 200, json: { body: { hello: 'world' } } });
  } finally { await close(server); }
});

test('serve returns 400 for malformed and non-JSON request bodies', async () => {
  const server = serve(0, new Map([['POST /echo', async () => ({ status: 200, json: {} })]]));
  try {
    await listen(server);
    const port = server.address().port;
    for (const [data, type] of [['{bad', 'application/json'], ['{}', 'text/plain']]) {
      const result = await new Promise((resolve, reject) => {
        const req = http.request({ host: '127.0.0.1', port, path: '/echo', method: 'POST', headers: { 'content-type': type } }, (res) => {
          let text = ''; res.setEncoding('utf8'); res.on('data', (c) => { text += c; }); res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(text) }));
        });
        req.on('error', reject); req.end(data);
      });
      assert.deepEqual(result, { status: 400, json: { error: 'bad_request' } });
    }
  } finally { await close(server); }
});

test('serve enforces the body cap while streaming', async () => {
  const server = serve(0, new Map([['POST /echo', async () => ({ status: 200, json: {} })]]), { maxBodyBytes: 8 });
  try {
    await listen(server);
    const result = await new Promise((resolve, reject) => {
      const req = http.request({ host: '127.0.0.1', port: server.address().port, path: '/echo', method: 'POST', headers: { 'content-type': 'application/json' } }, (res) => {
        let text = ''; res.setEncoding('utf8'); res.on('data', (c) => { text += c; }); res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(text) }));
      });
      req.on('error', reject); req.end('{"large":1}');
    });
    assert.deepEqual(result, { status: 413, json: { error: 'body_too_large' } });
  } finally { await close(server); }
});

test('call rejects an invalid route and times out', async () => {
  const server = serve(0, new Map());
  try {
    await listen(server);
    assert.deepEqual(await call(`http://127.0.0.1:${server.address().port}/missing`, 'GET', null),
      { status: 404, json: { error: 'not_found' } });
  } finally { await close(server); }
  await assert.rejects(call('http://127.0.0.1:1/', 'GET', null, { timeoutMs: 50 }), /ECONNREFUSED|timeout/i);
});
