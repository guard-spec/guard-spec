// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

const BROWSERS: [string[], string][] = [
  [['Edg/', 'EdgA/', 'EdgiOS/', 'Edge/'], 'Edge'],
  [['OPR/', 'Opera'], 'Opera'],
  [['Firefox/', 'FxiOS/'], 'Firefox'],
  [['HeadlessChrome/'], 'Headless Chrome'],
  [['Chrome/', 'CriOS/'], 'Chrome'],
];

const SYSTEMS: [string[], string][] = [
  [['iPhone', 'iPad', 'iPod'], 'iOS'],
  [['Android'], 'Android'],
  [['Mac OS X', 'Macintosh'], 'macOS'],
  [['Windows'], 'Windows'],
  [['CrOS'], 'ChromeOS'],
  [['Linux'], 'Linux'],
];

function first(s: string, table: [string[], string][]): string | null {
  for (const [marks, name] of table) if (marks.some((m) => s.includes(m))) return name;
  return null;
}

/** A short name for a session's user agent: "Chrome on macOS", or an API client for scripts. */
export function describeUserAgent(ua: string | null | undefined): { browser: string | null; os: string | null; client: boolean } {
  const s = (ua ?? '').trim();
  // Browsers all start with Mozilla/5.0; curl, node, python, Go, Postman... do not.
  if (!s.startsWith('Mozilla/')) return { browser: null, os: null, client: true };
  let browser = first(s, BROWSERS);
  if (!browser && s.includes('Safari/') && s.includes('Version/')) browser = 'Safari';
  return { browser, os: first(s, SYSTEMS), client: false };
}
