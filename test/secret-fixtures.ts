// Synthetic credential shapes for tests (security P0, 17 Nov 2026). Built at runtime from pieces:
// no literal here is a key, and gitleaks does not fire on the source.

export const j = (...p: string[]) => p.join('');
export const X0 = (n: number) => 'X0'.repeat(n);
export const ELL = '…';

// Provider prefixes, assembled so the source never holds one next to key characters.
export const P = {
  google: j('AI', 'za'),
  openai: j('sk', '-'),
  openaiProj: j('sk', '-proj-'),
  anthropic: j('sk', '-ant-'),
  ghp: j('gh', 'p_'),
  ghs: j('gh', 's_'),
  ghPat: j('github', '_pat_'),
  slack: j('xo', 'xb-'),
  akia: j('AK', 'IA'),
  asia: j('AS', 'IA'),
  stripe: j('sk', '_live_'),
  stripeR: j('rk', '_live_'),
  fly: j('fo', '1_'),
  flyV1: j('Fly', 'V1 fm2_'),
  neon: j('np', 'g_'),
};

/** A full-length synthetic Google API key (prefix + 35 key characters). */
export const fakeGoogleKey = () => j(P.google, 'Sy', X0(16), 'X');
/** The shape that leaked (prefix, ellipsis, 5 tail characters), synthetic. */
export const fakeMaskedGoogle = () => j(P.google, ELL, 'X0X0X');

