'use strict';
// @ts-check
// Reorder buffer (P1-11, architecture §15.2).
//
// watermark = max corrected time seen (clock-supported events only) − lateness.
// The collector clock (latest receipt time) also advances it, as a lateness
// timer would: an event is released no later than orderMs + lateness, so the
// wait is bounded by the lateness ("up to 5 s", architecture §15.3) even when
// no newer event arrives. Buffered events are released in (orderMs, ingestIdx)
// order once orderMs ≤ watermark. An event that arrives already below the
// watermark is released at once and marked `late` (never dropped).
// Clock-unsupported events are ordered by their receipt time and do not move
// the event-time watermark.
//
// Each released event gets `releasedAtMs`: the simulated collector time of its
// release (never before its receipt). Time-to-alert includes this wait.
//
// order_uncertain: two events of the same actor and session whose uncertainty
// intervals [t − u, t + u] overlap (|Δt| ≤ u1 + u2) are both flagged.

/** @typedef {import('./ingest.cjs').DetectEvent & { orderMs: number, releasedAtMs?: number }} TimedEvent */

const keyOf = (/** @type {TimedEvent} */ ev) => JSON.stringify([ev.actor, ev.session]);
const byOrder = (/** @type {TimedEvent} */ a, /** @type {TimedEvent} */ b) => a.orderMs - b.orderMs || a.ingestIdx - b.ingestIdx;

class ReorderBuffer {
  /** @param {{ latenessMs?: number, uncertaintyMs?: number }} [opts] */
  constructor({ latenessMs = 5000, uncertaintyMs = 250 } = {}) {
    this.latenessMs = latenessMs;
    this.uncertaintyMs = uncertaintyMs;
    this.maxCorrectedMs = -Infinity;
    this.nowMs = -Infinity; // simulated collector clock: latest receipt seen
    /** @type {TimedEvent[]} */
    this.pending = [];
    /** @type {Map<string, TimedEvent[]>} recently released, per (actor, session) */
    this.recent = new Map();
  }

  /** Event-time watermark: max corrected time seen − lateness. */
  get watermarkMs() { return this.maxCorrectedMs - this.latenessMs; }

  /** Watermark including the collector clock (lateness timer). */
  get effectiveWatermarkMs() { return Math.max(this.maxCorrectedMs, this.nowMs) - this.latenessMs; }

  /**
   * Release pending events with orderMs ≤ limit, in order. An event leaves at
   * the earlier of `atMs` and its lateness deadline, never before its receipt.
   * @param {number} limit @param {number} atMs @returns {TimedEvent[]}
   */
  _releaseUpTo(limit, atMs) {
    this.pending.sort(byOrder);
    let k = 0;
    while (k < this.pending.length && this.pending[k].orderMs <= limit) k++;
    const out = this.pending.splice(0, k);
    for (const e of out) e.releasedAtMs = Math.max(e.receivedMs, Math.min(atMs, e.orderMs + this.latenessMs));
    return out;
  }

  /** @param {TimedEvent} ev @returns {TimedEvent[]} events released up to and by this arrival */
  push(ev) {
    // The collector clock reaches this receipt: lateness timers that fired meanwhile release first.
    this.nowMs = Math.max(this.nowMs, ev.receivedMs);
    const out = this._releaseUpTo(this.nowMs - this.latenessMs, this.nowMs);
    if (ev.orderMs < this.effectiveWatermarkMs) {
      ev.late = true;
      ev.releasedAtMs = ev.receivedMs;
      out.push(ev);
    } else {
      this.pending.push(ev);
    }
    if (!ev.clockUnsupported && /** @type {number} */ (ev.correctedMs) > this.maxCorrectedMs) {
      this.maxCorrectedMs = /** @type {number} */ (ev.correctedMs);
    }
    out.push(...this._releaseUpTo(this.effectiveWatermarkMs, this.nowMs));
    this._markOverlaps(out);
    return out;
  }

  /** Release everything still buffered (end of stream). @returns {TimedEvent[]} */
  flush() {
    const out = this._releaseUpTo(Infinity, Infinity);
    this._markOverlaps(out);
    return out;
  }

  /** @param {TimedEvent[]} batch */
  _markOverlaps(batch) {
    const horizon = 2 * this.latenessMs + 4 * this.uncertaintyMs;
    for (const ev of batch) {
      const key = keyOf(ev);
      const list = this.recent.get(key) || [];
      for (const other of list) {
        if (Math.abs(ev.orderMs - other.orderMs) <= ev.uncertaintyMs + other.uncertaintyMs) {
          ev.orderUncertain = true;
          other.orderUncertain = true;
        }
      }
      list.push(ev);
      this.recent.set(key, list.filter((e) => Math.abs(ev.orderMs - e.orderMs) <= horizon));
    }
  }
}

module.exports = { ReorderBuffer };
