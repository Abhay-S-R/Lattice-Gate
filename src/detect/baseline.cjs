'use strict';
// @ts-check
// Service-edge baseline (P1-10 [v0.3], D-09): a global set of directed edges,
// seeded from the documented expected edges plus an optional benign warm-up
// corpus. Never learned from the stream being evaluated (no cold start).

const fs = require('node:fs');
const { DOCUMENTED_PRACTICE_EDGES } = require('./config.cjs');

/** Collision-free key for a directed edge (service names may contain any delimiter). */
const edgeKey = (/** @type {string} */ src, /** @type {string} */ dst) => JSON.stringify([src, dst]);

/** @param {unknown} e @returns {[string, string]} */
function asEdge(e) {
  /** @type {any} */
  const x = e;
  const pair = Array.isArray(x) ? x : (x && typeof x === 'object' ? [x.src, x.dst] : null);
  if (!pair || pair.length !== 2 || typeof pair[0] !== 'string' || typeof pair[1] !== 'string' || pair[0] === '' || pair[1] === '') {
    throw new TypeError('baseline edge must be [src, dst] or { src, dst } with non-empty service names');
  }
  return [pair[0], pair[1]];
}

class Baseline {
  /** @param {{ source?: string }} [meta] */
  constructor(meta = {}) {
    /** @type {Set<string>} */
    this.edges = new Set();
    this.source = meta.source || 'custom';
    this.documentedEdgeCount = 0;
    this.corpusEdgeCount = 0;
    /** @type {number|null} */
    this.seed = null;
  }

  /**
   * @param {Iterable<unknown>} [edges]
   * @param {{ source?: string }} [meta]
   */
  static fromDocumented(edges = DOCUMENTED_PRACTICE_EDGES, meta = { source: 'documented' }) {
    const b = new Baseline(meta);
    for (const e of edges) b.addEdge(...asEdge(e));
    b.documentedEdgeCount = b.edges.size;
    return b;
  }

  /** `{ edges: [[src, dst] | {src, dst}, ...], source?, seed? }` @param {string} filePath */
  static fromFile(filePath) {
    const obj = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    if (!obj || typeof obj !== 'object' || !Array.isArray(obj.edges)) throw new TypeError('baseline file must have an "edges" array');
    const b = Baseline.fromDocumented(obj.edges, { source: typeof obj.source === 'string' && obj.source ? obj.source : 'file' });
    if (Number.isSafeInteger(obj.seed)) b.seed = obj.seed;
    return b;
  }

  /** @param {string} src @param {string} dst */
  addEdge(src, dst) { this.edges.add(edgeKey(src, dst)); }

  /**
   * Add every edge of a benign warm-up corpus (kept separate from evaluation data).
   * @param {Iterable<{ src: string, dst: string }>} events
   * @param {{ seed?: number }} [meta]
   */
  addCorpus(events, { seed } = {}) {
    const before = this.edges.size;
    for (const ev of events) this.addEdge(ev.src, ev.dst);
    this.corpusEdgeCount += this.edges.size - before;
    if (seed !== undefined) this.seed = seed;
    if (!this.source.endsWith('+warmup')) this.source += '+warmup';
    return this;
  }

  /** @param {string} src @param {string} dst */
  has(src, dst) { return this.edges.has(edgeKey(src, dst)); }

  summary() {
    return {
      source: this.source,
      edgeCount: this.edges.size,
      documentedEdgeCount: this.documentedEdgeCount,
      corpusEdgeCount: this.corpusEdgeCount,
      seed: this.seed,
    };
  }
}

module.exports = { Baseline, edgeKey };
