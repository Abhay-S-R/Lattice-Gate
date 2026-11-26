'use strict';
// Small loopback-only JSON transport shared by the control plane and nodes.
const http = require('node:http');
const { LOOPBACK, HTTP } = require('./contracts.cjs');

const response = (res, status, json) => {
  const body = Buffer.from(JSON.stringify(json));
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': body.length, connection: 'close' });
  res.end(body);
};

async function readJson(req, limit) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) return { tooLarge: true };
    chunks.push(chunk);
  }
  if (size === 0) return { body: null };
  const type = String(req.headers['content-type'] || '').split(';', 1)[0].trim().toLowerCase();
  if (type !== 'application/json') return { invalid: true };
  try { return { body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }; } catch { return { invalid: true }; }
}

/** @param {number} port @param {Map<string, Function>} routes */
function serve(port, routes, { maxBodyBytes = HTTP.maxBodyBytes } = {}) {
  const server = http.createServer(async (req, res) => {
    const handler = routes.get(`${req.method} ${new URL(req.url || '/', 'http://127.0.0.1').pathname}`);
    if (!handler) { response(res, 404, { error: 'not_found' }); return; }
    const parsed = await readJson(req, maxBodyBytes);
    if (parsed.tooLarge) { response(res, 413, { error: 'body_too_large' }); return; }
    if (parsed.invalid) { response(res, 400, { error: 'bad_request' }); return; }
    try {
      const result = await handler(parsed.body, req);
      if (!result || !Number.isInteger(result.status) || result.status < 100 || result.status > 599 ||
          !result.json || typeof result.json !== 'object' || Array.isArray(result.json)) {
        response(res, 500, { error: 'internal_error' }); return;
      }
      response(res, result.status, result.json);
    } catch {
      response(res, 500, { error: 'internal_error' });
    }
  });
  server.requestTimeout = HTTP.timeoutMs;
  server.headersTimeout = Math.max(HTTP.timeoutMs + 1000, 6000);
  server.listen(port, LOOPBACK);
  return server;
}

/** @param {string} address Full URL, including the route path. @param {string} method @param {unknown} json @param {{timeoutMs?:number}} [options] */
function call(address, method, json, { timeoutMs = HTTP.timeoutMs } = {}) {
  if (!/^(GET|POST|PUT|DELETE)$/.test(method)) return Promise.reject(new TypeError('invalid method'));
  const url = new URL(address);
  const payload = json === null || json === undefined ? null : Buffer.from(JSON.stringify(json));
  return new Promise((resolve, reject) => {
    const req = http.request(url, {
      method,
      headers: payload ? { 'content-type': 'application/json', 'content-length': payload.length } : {},
      timeout: timeoutMs,
    }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (chunk) => { size += chunk.length; if (size > HTTP.maxBodyBytes) { req.destroy(new Error('response too large')); return; } chunks.push(chunk); });
      res.on('end', () => {
        let body;
        try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { reject(new Error('invalid JSON response')); return; }
        resolve({ status: res.statusCode || 0, json: body });
      });
    });
    req.on('timeout', () => req.destroy(new Error('request timeout')));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

module.exports = { serve, call };
