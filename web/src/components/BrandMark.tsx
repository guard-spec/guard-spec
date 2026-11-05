// Copyright 2026 The Guard Spec Authors
// SPDX-License-Identifier: Apache-2.0

// The Guard Spec mark: a shield in two tones with three filter bars, one per
// detection layer (rules, classifier, embeddings). Colors come from the
// --brand tokens, so it follows the theme. public/favicon.svg is the same
// drawing with the light-theme colors.
export function BrandMark({ size = 26 }: { size?: number }) {
  return (
    <svg viewBox="0 0 32 32" width={size} height={size} aria-hidden="true">
      <path d="M16 1.5 3.5 6.5v8.3c0 7.7 5.3 13.8 12.5 15.7 7.2-1.9 12.5-8 12.5-15.7V6.5z" className="brand-shield" />
      <path d="M16 1.5v29c7.2-1.9 12.5-8 12.5-15.7V6.5z" className="brand-shield-side" />
      <path d="M10 11h12M11.5 16h9M13.5 21h5" className="brand-bars" />
    </svg>
  );
}
