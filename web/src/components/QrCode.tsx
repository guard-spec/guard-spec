// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import qrcode from 'qrcode-generator';
import { useMemo } from 'react';

/**
 * A QR code drawn in the browser as SVG (no external QR service, no data:
 * URL: the CSP allows neither). Used for the otpauth:// URL of 2FA setup.
 */
export function QrCode({ text, label, size = 184 }: { text: string; label: string; size?: number }) {
  const path = useMemo(() => {
    const qr = qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    const n = qr.getModuleCount();
    let d = '';
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) {
        if (qr.isDark(r, c)) d += `M${c + 4} ${r + 4}h1v1h-1z`;
      }
    }
    return { d, n: n + 8 };
  }, [text]);
  return (
    <svg className="qr" role="img" aria-label={label} width={size} height={size} viewBox={`0 0 ${path.n} ${path.n}`} shapeRendering="crispEdges">
      <rect width={path.n} height={path.n} className="qr-bg" />
      <path d={path.d} className="qr-fg" />
    </svg>
  );
}
