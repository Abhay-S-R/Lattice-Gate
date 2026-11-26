'use strict';

const MAX_RETRIES = 3;

function mulberry32(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6D2B79F5) >>> 0;
    let x = state;
    x = Math.imul(x ^ (x >>> 15), x | 1);
    x ^= x + Math.imul(x ^ (x >>> 7), x | 61);
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
}

class TransportSim {
  constructor(seed, { drop = 0, dup = 0, reorder = 0, delay = 0, retries = MAX_RETRIES } = {}) {
    if (!Number.isSafeInteger(seed) || seed < 0 || seed > 0xffffffff) throw new RangeError('seed must be a uint32');
    for (const [name, value] of Object.entries({ drop, dup, reorder })) {
      if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1) throw new RangeError(`${name} must be between 0 and 1`);
    }
    if (!Number.isSafeInteger(delay) || delay < 0 || delay > 5000) throw new RangeError('delay must be between 0 and 5000 ms');
    if (!Number.isSafeInteger(retries) || retries < 0 || retries > MAX_RETRIES) throw new RangeError('retries must be between 0 and 3');
    this.random = mulberry32(seed);
    this.options = { drop, dup, reorder, delay, retries };
  }

  deliver(records, receive) {
    if (!Array.isArray(records) || typeof receive !== 'function') throw new TypeError('deliver requires records and a receiver');
    const { drop, dup, reorder, delay, retries } = this.options;
    const packets = [];
    const missing = [];
    let attempts = 0, receipts = 0, duplicateCopies = 0;
    for (const record of records) {
      let received = false;
      for (let attempt = 0; attempt <= retries; attempt++) {
        attempts++;
        if (this.random() < drop) continue;
        received = true;
        receipts++;
        packets.push({ record, delay_ms: delay ? Math.floor(this.random() * (delay + 1)) : 0, attempt });
        if (this.random() < dup) {
          duplicateCopies++;
          packets.push({ record, delay_ms: delay ? Math.floor(this.random() * (delay + 1)) : 0, attempt, duplicate: true });
        }
        break;
      }
      if (!received) missing.push(record);
    }
    if (reorder > 0 && packets.length > 1 && this.random() < reorder) {
      for (let i = packets.length - 1; i > 0; i--) {
        const j = Math.floor(this.random() * (i + 1));
        [packets[i], packets[j]] = [packets[j], packets[i]];
      }
    } else packets.sort((a, b) => a.delay_ms - b.delay_ms);
    const arrivals = [];
    for (const packet of packets) {
      try { arrivals.push({ packet, result: receive(packet.record, packet) }); }
      catch (error) { arrivals.push({ packet, error: error?.message || 'delivery_failed' }); }
    }
    return {
      transport: { records: records.length, attempts, receipts, retries: attempts - records.length, duplicateCopies, missing: missing.length },
      missing, arrivals,
    };
  }
}

module.exports = { TransportSim, mulberry32, MAX_RETRIES };
