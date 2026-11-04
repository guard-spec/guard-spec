// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Finds the text offset of a path such as policies[0].rules[1].when in a
// block-style YAML document, so a server error can be shown at its line.
// A heuristic over indentation (no YAML parser); returns undefined when the
// path cannot be followed.

type Seg = { key: string } | { index: number };

export function parsePath(path: string): Seg[] {
  const segs: Seg[] = [];
  for (const m of path.matchAll(/([^.[\]]+)|\[(\d+)\]/g)) {
    if (m[2] !== undefined) segs.push({ index: Number(m[2]) });
    else if (m[1] !== undefined) segs.push({ key: m[1] });
  }
  return segs;
}

interface Line {
  start: number;
  indent: number;
  text: string;
}

function lines(doc: string): Line[] {
  const out: Line[] = [];
  let start = 0;
  for (const raw of doc.split('\n')) {
    const trimmed = raw.trimStart();
    if (trimmed !== '' && !trimmed.startsWith('#')) {
      out.push({ start, indent: raw.length - trimmed.length, text: trimmed });
    }
    start += raw.length + 1;
  }
  return out;
}

/** Returns the offset of the line the path points at, or undefined. */
export function locatePath(doc: string, path: string): number | undefined {
  const ls = lines(doc);
  let from = 0; // index into ls where the current node's children start
  let to = ls.length; // exclusive end of the current node
  let minIndent = -1; // children are indented more than this
  let found: number | undefined;
  for (const seg of parsePath(path)) {
    let hit = -1;
    if ('key' in seg) {
      // The first line in range at the children's indentation that starts with "key:" (or "- key:").
      let childIndent = -1;
      for (let i = from; i < to; i++) {
        const l = ls[i];
        if (!l) continue;
        const text = l.text.startsWith('- ') ? l.text.slice(2) : l.text;
        // The key after "- " sits two columns right of the dash.
        const indent = l.text.startsWith('- ') ? l.indent + 2 : l.indent;
        if (indent <= minIndent) continue;
        if (childIndent === -1) childIndent = indent;
        if (indent !== childIndent) continue;
        if (text.startsWith(seg.key + ':')) {
          hit = i;
          break;
        }
      }
      if (hit === -1) return undefined;
      const hl = ls[hit];
      if (!hl) return undefined;
      const keyIndent = hl.text.startsWith('- ') ? hl.indent + 2 : hl.indent;
      found = hl.start + hl.indent + (hl.text.startsWith('- ') ? 2 : 0);
      let end = hit + 1;
      while (end < to && (ls[end]?.indent ?? 0) > keyIndent) end++;
      // A sequence under the key may sit at the same indent as the key.
      while (end < to && ls[end]?.indent === keyIndent && ls[end]?.text.startsWith('- ')) {
        end++;
        while (end < to && (ls[end]?.indent ?? 0) > keyIndent) end++;
      }
      from = hit + 1;
      to = end;
      minIndent = keyIndent - 1;
    } else {
      let n = -1;
      let itemIndent = -1;
      for (let i = from; i < to; i++) {
        const l = ls[i];
        if (!l?.text.startsWith('- ')) continue;
        if (itemIndent === -1) itemIndent = l.indent;
        if (l.indent !== itemIndent) continue;
        n++;
        if (n === seg.index) {
          hit = i;
          break;
        }
      }
      if (hit === -1) return undefined;
      const hl = ls[hit];
      if (!hl) return undefined;
      found = hl.start + hl.indent;
      let end = hit + 1;
      while (end < to && (ls[end]?.indent ?? 0) > itemIndent) end++;
      // The item's own first line holds its first key: search from it.
      from = hit;
      to = end;
      minIndent = itemIndent;
    }
  }
  return found;
}
