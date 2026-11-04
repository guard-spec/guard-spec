// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The notification stream (GET /v1/notifications/stream, contract §6): a
// text/event-stream read with fetch, so the token travels in the
// Authorization header and never in the URL (EventSource cannot send
// headers). connect-src 'self' covers it.

export interface SseEvent {
  event: string;
  data: string;
  id: string | null;
}

/**
 * An incremental parser of the event-stream format: push chunks of text,
 * get the complete events. Comments (": heartbeat") are skipped.
 */
export class SseParser {
  private buf = '';
  private data: string[] = [];
  private event = '';
  private id: string | null = null;

  push(chunk: string): SseEvent[] {
    this.buf += chunk;
    const out: SseEvent[] = [];
    for (;;) {
      const m = /\r\n|\r|\n/.exec(this.buf);
      // A lone \r at the end may be the first half of \r\n: wait for more.
      if (!m || (m[0] === '\r' && m.index === this.buf.length - 1)) break;
      const line = this.buf.slice(0, m.index);
      this.buf = this.buf.slice(m.index + m[0].length);
      if (line === '') {
        if (this.data.length > 0) out.push({ event: this.event || 'message', data: this.data.join('\n'), id: this.id });
        this.data = [];
        this.event = '';
        continue;
      }
      if (line.startsWith(':')) continue;
      const colon = line.indexOf(':');
      const field = colon < 0 ? line : line.slice(0, colon);
      let value = colon < 0 ? '' : line.slice(colon + 1);
      if (value.startsWith(' ')) value = value.slice(1);
      if (field === 'data') this.data.push(value);
      else if (field === 'event') this.event = value;
      else if (field === 'id') this.id = value;
    }
    return out;
  }
}

/** The wait before reconnect number attempt (0-based): 1 s doubling to 30 s, ±20% jitter. */
export function backoffDelay(attempt: number, random: () => number = Math.random): number {
  const base = Math.min(30_000, 1000 * 2 ** Math.min(attempt, 5));
  return Math.round(base * (0.8 + 0.4 * random()));
}

export type StreamEnd = 'closed' | 'unauthorized' | 'unavailable';

/**
 * Reads the stream until it ends or signal aborts. Resolves with why it ended:
 * closed (reconnect), unauthorized (401: stop) or unavailable (404/405: no
 * such endpoint on this control plane: stop). Network errors reject.
 */
export async function readStream(opts: {
  url: string;
  token: string;
  signal: AbortSignal;
  onOpen?: () => void;
  onEvent: (e: SseEvent) => void;
  fetchImpl?: typeof fetch;
}): Promise<StreamEnd> {
  const f = opts.fetchImpl ?? ((i: RequestInfo | URL, init?: RequestInit) => globalThis.fetch(i, init));
  const res = await f(opts.url, {
    headers: { Accept: 'text/event-stream', Authorization: `Bearer ${opts.token}` },
    credentials: 'same-origin',
    cache: 'no-store',
    signal: opts.signal,
  });
  if (res.status === 401) return 'unauthorized';
  if (res.status === 404 || res.status === 405) return 'unavailable';
  if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
  opts.onOpen?.();
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  const parser = new SseParser();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      for (const e of parser.push(decoder.decode(value, { stream: true }))) opts.onEvent(e);
    }
    // An event cut off by the end of the stream is dropped (as EventSource does).
    for (const e of parser.push(decoder.decode())) opts.onEvent(e);
  } finally {
    reader.releaseLock();
  }
  return 'closed';
}
