'use strict';
// @ts-check
// Clock correction (P1-11, architecture §15.2).
//   corrected = event_time − source_clock_offset   (collector clock)
//   delay     = received − corrected
// Offsets beyond ±maxOffsetMs are flagged clockUnsupported, never clamped: the
// event is kept, ordered by receipt, and its order is uncertain.

/**
 * @param {import('./ingest.cjs').DetectEvent} ev
 * @param {{ maxOffsetMs?: number, uncertaintyMs?: number }} [opts]
 * @returns {import('./ingest.cjs').DetectEvent & { orderMs: number }} a new object; `ev` is not modified
 */
function correct(ev, { maxOffsetMs = 5000, uncertaintyMs = 250 } = {}) {
  const correctedMs = ev.eventTimeMs - ev.offsetMs;
  const clockUnsupported = Math.abs(ev.offsetMs) > maxOffsetMs;
  return {
    ...ev,
    correctedMs,
    deliveryDelayMs: ev.receivedMs - correctedMs,
    clockUnsupported,
    uncertaintyMs,
    orderUncertain: ev.orderUncertain || clockUnsupported,
    // The time used for ordering, windows and approval checks.
    orderMs: clockUnsupported ? ev.receivedMs : correctedMs,
  };
}

module.exports = { correct };
