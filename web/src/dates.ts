// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// One date formatter for the whole UI, in the UI language (App sets it).

let locale = 'en-US';

export function localeOf(lang: string): string {
  return lang === 'vi' ? 'vi-VN' : 'en-US';
}

/** Called when the UI language changes. */
export function setDateLocale(lang: string): void {
  locale = localeOf(lang);
}

function parse(s: string | number | Date | null | undefined): Date | null {
  if (s === null || s === undefined || s === '') return null;
  const d = s instanceof Date ? s : new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** "Nov 4, 2026, 7:40 PM" / "4 thg 11, 2026, 19:40". */
export function formatDateTime(s: string | number | Date | null | undefined, loc = locale): string {
  const d = parse(s);
  if (!d) return typeof s === 'string' && s !== '' ? s : '—';
  return new Intl.DateTimeFormat(loc, { dateStyle: 'medium', timeStyle: 'short' }).format(d);
}

/** "Nov 4, 2026": a day, for columns where the time does not matter. */
export function formatDate(s: string | number | Date | null | undefined, loc = locale): string {
  const d = parse(s);
  if (!d) return '—';
  return new Intl.DateTimeFormat(loc, { dateStyle: 'medium' }).format(d);
}

/** "Nov 4, 07:40 PM": axes and short labels. */
export function formatShort(s: string | number | Date | null | undefined, loc = locale): string {
  const d = parse(s);
  if (!d) return '—';
  return new Intl.DateTimeFormat(loc, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(d);
}

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ['year', 365 * 86_400_000],
  ['month', 30 * 86_400_000],
  ['week', 7 * 86_400_000],
  ['day', 86_400_000],
  ['hour', 3_600_000],
  ['minute', 60_000],
];

/** "5 minutes ago", "3 days ago", "just now"; now is injectable for tests. */
export function formatRelative(s: string | number | Date | null | undefined, now = Date.now(), loc = locale): string {
  const d = parse(s);
  if (!d) return '—';
  const diff = d.getTime() - now;
  const rtf = new Intl.RelativeTimeFormat(loc, { numeric: 'auto' });
  for (const [unit, ms] of UNITS) {
    if (Math.abs(diff) >= ms) return rtf.format(Math.round(diff / ms), unit);
  }
  return rtf.format(0, 'second');
}
