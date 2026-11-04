// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

// The control plane serves this build at /ui/ (go:embed web/dist) under a
// strict CSP (cmd/control-plane/ui.go): no inline scripts or styles. vite
// preview sends the same policy, minus data: images (the UI uses none), so the
// e2e tests run the build under it and fail on any violation.
export const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "form-action 'self'",
].join('; ');

const securityHeaders = {
  'Content-Security-Policy': CSP,
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
};

export default defineConfig({
  base: '/ui/',
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: false,
    // Inline nothing: a data: URL would need img-src/font-src data:.
    assetsInlineLimit: 0,
    chunkSizeWarningLimit: 700,
    rolldownOptions: {
      output: {
        // Vendor chunks: React loads with the shell; the diagram, the query
        // builder and CodeMirror load with the pages that use them.
        codeSplitting: {
          groups: [
            { name: 'react', test: /node_modules[\\/](react|react-dom|scheduler)[\\/]/, priority: 40 },
            { name: 'codemirror', test: /node_modules[\\/](@codemirror|@lezer|style-mod|crelt|w3c-keyname)[\\/]/, priority: 30 },
            { name: 'diagram', test: /node_modules[\\/](@xyflow|d3-[^/\\]+|@dagrejs|zustand|classcat)[\\/]/, priority: 20 },
            { name: 'querybuilder', test: /node_modules[\\/](react-querybuilder|@react-querybuilder|immer|@reduxjs|redux[^/\\]*)[\\/]/, priority: 10 },
          ],
        },
      },
    },
  },
  server: {
    port: 5173,
    headers: { 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' },
    proxy: {
      '/v1': { target: 'http://localhost:18081', changeOrigin: true },
    },
  },
  preview: {
    port: 4173,
    strictPort: true,
    headers: securityHeaders,
    // No proxy: the e2e tests mock /v1 and must never reach a real backend.
    proxy: {},
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
});
