// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// Draws labelled connectors between elements of #canvas on an overlay SVG.
// link(from, to, {from:'r', to:'l', color, dash, label, labelColor, both, t, bend})
const NS = 'http://www.w3.org/2000/svg';
function anchor(el, side, off) {
  const c = document.getElementById('canvas').getBoundingClientRect();
  const r = el.getBoundingClientRect();
  const x0 = r.left - c.left, y0 = r.top - c.top;
  const o = off || 0;
  switch (side) {
    case 'l': return [x0, y0 + r.height / 2 + o, -1, 0];
    case 'r': return [x0 + r.width, y0 + r.height / 2 + o, 1, 0];
    case 't': return [x0 + r.width / 2 + o, y0, 0, -1];
    case 'b': return [x0 + r.width / 2 + o, y0 + r.height, 0, 1];
  }
}
function marker(svg, id, color) {
  let defs = svg.querySelector('defs') || svg.appendChild(document.createElementNS(NS, 'defs'));
  if (svg.querySelector('#' + id)) return;
  const m = document.createElementNS(NS, 'marker');
  m.setAttribute('id', id); m.setAttribute('viewBox', '0 0 10 10'); m.setAttribute('refX', '8'); m.setAttribute('refY', '5');
  m.setAttribute('markerWidth', '7'); m.setAttribute('markerHeight', '7'); m.setAttribute('orient', 'auto-start-reverse');
  const p = document.createElementNS(NS, 'path'); p.setAttribute('d', 'M0,0 L10,5 L0,10 z'); p.setAttribute('fill', color);
  m.appendChild(p); defs.appendChild(m);
}
function link(a, b, o) {
  const svg = document.getElementById('wires');
  const A = anchor(document.getElementById(a), o.from, o.fromOff), B = anchor(document.getElementById(b), o.to, o.toOff);
  const k = o.bend ?? 0.45;
  const d = Math.max(60, Math.hypot(B[0] - A[0], B[1] - A[1]) * k);
  const c1 = [A[0] + A[2] * d, A[1] + A[3] * d], c2 = [B[0] + B[2] * d, B[1] + B[3] * d];
  const color = o.color || '#475569';
  const id = 'm' + color.replace('#', '');
  marker(svg, id, color);
  const p = document.createElementNS(NS, 'path');
  p.setAttribute('d', `M${A[0]},${A[1]} C${c1[0]},${c1[1]} ${c2[0]},${c2[1]} ${B[0]},${B[1]}`);
  p.setAttribute('fill', 'none'); p.setAttribute('stroke', color); p.setAttribute('stroke-width', o.width || 2.4);
  p.setAttribute('stroke-linecap', 'round');
  if (o.dash) p.setAttribute('stroke-dasharray', o.dash);
  p.setAttribute('marker-end', `url(#${id})`);
  if (o.both) p.setAttribute('marker-start', `url(#${id})`);
  svg.appendChild(p);
  if (o.label) {
    const t = o.t ?? 0.5, u = 1 - t;
    const x = u*u*u*A[0] + 3*u*u*t*c1[0] + 3*u*t*t*c2[0] + t*t*t*B[0] + (o.dx || 0);
    const y = u*u*u*A[1] + 3*u*u*t*c1[1] + 3*u*t*t*c2[1] + t*t*t*B[1] + (o.dy || 0);
    const l = document.createElement('div');
    l.className = 'wire-label'; l.innerHTML = o.label;
    l.style.borderColor = color; l.style.color = o.labelColor || color;
    document.getElementById('canvas').appendChild(l);
    l.style.left = (x - l.offsetWidth / 2) + 'px'; l.style.top = (y - l.offsetHeight / 2) + 'px';
  }
}
