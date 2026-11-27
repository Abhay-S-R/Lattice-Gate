'use strict';
// Render docs/brief/brief.html → docs/brief/brief.pdf (A4) with headless Chrome or Edge,
// and fail unless the PDF has exactly 2 pages (the submission limit).
// Usage: node scripts/render-brief.cjs   (set CHROME=<path> if the browser is elsewhere)
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { pathToFileURL } = require('node:url');

const REPO = path.resolve(__dirname, '..');
const SRC = path.join(REPO, 'docs', 'brief', 'brief.html');
const OUT = path.join(REPO, 'docs', 'brief', 'brief.pdf');

const candidates = [
  process.env.CHROME,
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  '/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
].filter(Boolean);
const browser = candidates.find((p) => fs.existsSync(p));
if (!browser) { process.stderr.write('Chrome/Edge not found (set CHROME=<path>)\n'); process.exit(2); }

// Render from a local copy: browsers can't always read UNC/WSL paths.
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'kig-brief-'));
const html = path.join(work, 'brief.html');
const pdf = path.join(work, 'brief.pdf');
fs.copyFileSync(SRC, html);
const r = spawnSync(browser, ['--headless=new', '--disable-gpu', '--no-pdf-header-footer',
  `--user-data-dir=${path.join(work, 'profile')}`, `--print-to-pdf=${pdf}`, pathToFileURL(html).href],
{ encoding: 'utf8', timeout: 60000 });
if (!fs.existsSync(pdf)) { process.stderr.write(`render failed: ${r.stderr || r.error}\n`); process.exit(1); }

const bytes = fs.readFileSync(pdf);
const pages = (bytes.toString('latin1').match(/\/Type\s*\/Page(?![s\w])/g) || []).length;
fs.copyFileSync(pdf, OUT);
fs.rmSync(work, { recursive: true, force: true });
process.stdout.write(`${OUT}: ${pages} page(s), ${bytes.length} bytes\n`);
process.exit(pages === 2 ? 0 : 1);
