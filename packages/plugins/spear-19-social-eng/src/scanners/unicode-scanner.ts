/**
 * SPEAR-19: Unicode Scanner
 *
 * Detects Unicode-based social engineering techniques in source code:
 *   - Bidirectional text control characters (Trojan Source)
 *   - Homoglyph substitution (Cyrillic/Greek lookalikes)
 *   - Zero-width characters (invisible data encoding)
 *   - Confusable symbol substitution
 *   - Right-to-left override attacks
 *
 * References:
 *   - CVE-2021-42574: Trojan Source -- Invisible Vulnerabilities
 *   - CVE-2021-42694: Homoglyph attacks in source code
 *   - Unicode Technical Report #36: Unicode Security Considerations
 */

import type { Finding } from '@wigtn/shared';

// ─── Unicode Character Ranges ───────────────────────────────────

/** Bidirectional control characters that can reorder displayed text. */
const BIDI_CONTROL_CHARS: ReadonlySet<number> = new Set([
  0x200E, // LEFT-TO-RIGHT MARK
  0x200F, // RIGHT-TO-LEFT MARK
  0x202A, // LEFT-TO-RIGHT EMBEDDING
  0x202B, // RIGHT-TO-LEFT EMBEDDING
  0x202C, // POP DIRECTIONAL FORMATTING
  0x202D, // LEFT-TO-RIGHT OVERRIDE
  0x202E, // RIGHT-TO-LEFT OVERRIDE
  0x2066, // LEFT-TO-RIGHT ISOLATE
  0x2067, // RIGHT-TO-LEFT ISOLATE
  0x2068, // FIRST STRONG ISOLATE
  0x2069, // POP DIRECTIONAL ISOLATE
]);

/** Zero-width and invisible characters. */
const ZERO_WIDTH_CHARS: ReadonlySet<number> = new Set([
  0x200B, // ZERO WIDTH SPACE
  0x200C, // ZERO WIDTH NON-JOINER
  0x200D, // ZERO WIDTH JOINER
  0x2060, // WORD JOINER
  0x2061, // FUNCTION APPLICATION
  0x2062, // INVISIBLE TIMES
  0x2063, // INVISIBLE SEPARATOR
  0x2064, // INVISIBLE PLUS
  0xFEFF, // ZERO WIDTH NO-BREAK SPACE (BOM)
  0x00AD, // SOFT HYPHEN
]);

/**
 * Cyrillic characters that are visual homoglyphs for Latin characters.
 * Maps Cyrillic code point to the Latin character it mimics.
 */
const CYRILLIC_HOMOGLYPHS: ReadonlyMap<number, string> = new Map([
  [0x0430, 'a'], // а -> a
  [0x0435, 'e'], // е -> e
  [0x043E, 'o'], // о -> o
  [0x0440, 'p'], // р -> p
  [0x0441, 'c'], // с -> c
  [0x0445, 'x'], // х -> x
  [0x0410, 'A'], // А -> A
  [0x0412, 'B'], // В -> B
  [0x0415, 'E'], // Е -> E
  [0x041A, 'K'], // К -> K
  [0x041C, 'M'], // М -> M
  [0x041D, 'H'], // Н -> H
  [0x041E, 'O'], // О -> O
  [0x0420, 'P'], // Р -> P
  [0x0421, 'C'], // С -> C
  [0x0422, 'T'], // Т -> T
  [0x0425, 'X'], // Х -> X
  [0x0443, 'y'], // у -> y (close enough)
  [0x0456, 'i'], // і -> i (Ukrainian i)
]);

/**
 * Greek characters that are visual homoglyphs for Latin characters.
 */
const GREEK_HOMOGLYPHS: ReadonlySet<number> = new Set([
  0x0391, // Α (Alpha) -> A
  0x0392, // Β (Beta) -> B
  0x0395, // Ε (Epsilon) -> E
  0x0396, // Ζ (Zeta) -> Z
  0x0397, // Η (Eta) -> H
  0x0399, // Ι (Iota) -> I
  0x039A, // Κ (Kappa) -> K
  0x039C, // Μ (Mu) -> M
  0x039D, // Ν (Nu) -> N
  0x039F, // Ο (Omicron) -> O
  0x03A1, // Ρ (Rho) -> P
  0x03A4, // Τ (Tau) -> T
  0x03A5, // Υ (Upsilon) -> Y
  0x03A7, // Χ (Chi) -> X
  0x03BF, // ο (omicron) -> o
]);

// ─── Scanner Interface ──────────────────────────────────────────

export interface UnicodeFinding {
  type: 'bidi' | 'homoglyph' | 'zero_width' | 'combining' | 'tag_char';
  line: number;
  column: number;
  codePoint: number;
  charName: string;
  context: string;
}

// ─── Scan Functions ─────────────────────────────────────────────

/**
 * Scan file content for bidirectional text control characters.
 *
 * These characters can reorder displayed text so that code appears
 * different from what is actually compiled/interpreted (Trojan Source).
 */
export function scanBidiCharacters(content: string): UnicodeFinding[] {
  const findings: UnicodeFinding[] = [];
  const lines = content.split('\n');

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx]!;
    for (let col = 0; col < line.length; col++) {
      const cp = line.codePointAt(col);
      if (cp !== undefined && BIDI_CONTROL_CHARS.has(cp)) {
        findings.push({
          type: 'bidi',
          line: lineIdx + 1,
          column: col + 1,
          codePoint: cp,
          charName: getBidiCharName(cp),
          context: extractContext(line, col),
        });
      }
    }
  }

  return findings;
}

/**
 * Scan file content for homoglyph characters (Cyrillic/Greek lookalikes).
 *
 * Mixed-script identifiers where some characters are Cyrillic or Greek
 * homoglyphs for Latin characters can create invisible variable shadowing.
 */
export function scanHomoglyphs(content: string): UnicodeFinding[] {
  const findings: UnicodeFinding[] = [];
  const lines = content.split('\n');

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx]!;

    // Skip comment-only lines
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) {
      continue;
    }

    for (let col = 0; col < line.length; col++) {
      const cp = line.codePointAt(col);
      if (cp === undefined) continue;

      if (CYRILLIC_HOMOGLYPHS.has(cp)) {
        findings.push({
          type: 'homoglyph',
          line: lineIdx + 1,
          column: col + 1,
          codePoint: cp,
          charName: `Cyrillic homoglyph for '${CYRILLIC_HOMOGLYPHS.get(cp)}' (U+${cp.toString(16).toUpperCase().padStart(4, '0')})`,
          context: extractContext(line, col),
        });
      } else if (GREEK_HOMOGLYPHS.has(cp)) {
        findings.push({
          type: 'homoglyph',
          line: lineIdx + 1,
          column: col + 1,
          codePoint: cp,
          charName: `Greek homoglyph (U+${cp.toString(16).toUpperCase().padStart(4, '0')})`,
          context: extractContext(line, col),
        });
      }
    }
  }

  return findings;
}

/**
 * Scan file content for zero-width and invisible characters.
 *
 * Sequences of zero-width characters can encode hidden data or
 * create invisible differences between identifiers.
 */
export function scanZeroWidthCharacters(content: string): UnicodeFinding[] {
  const findings: UnicodeFinding[] = [];
  const lines = content.split('\n');

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx]!;
    for (let col = 0; col < line.length; col++) {
      const cp = line.codePointAt(col);
      if (cp !== undefined && ZERO_WIDTH_CHARS.has(cp)) {
        // Skip lone BOM at start of file
        if (cp === 0xFEFF && lineIdx === 0 && col === 0) {
          continue;
        }
        findings.push({
          type: 'zero_width',
          line: lineIdx + 1,
          column: col + 1,
          codePoint: cp,
          charName: getZeroWidthCharName(cp),
          context: extractContext(line, col),
        });
      }
    }
  }

  return findings;
}

/**
 * Convert all Unicode findings into SpearPlugin Finding objects.
 */
export function unicodeFindingsToFindings(
  unicodeFindings: UnicodeFinding[],
  filePath: string,
  pluginId: string,
): Finding[] {
  return unicodeFindings.map((uf) => {
    const severityMap: Record<UnicodeFinding['type'], 'critical' | 'high' | 'medium'> = {
      bidi: 'critical',
      homoglyph: 'high',
      zero_width: 'high',
      combining: 'medium',
      tag_char: 'critical',
    };

    return {
      ruleId: `soceng-unicode-${uf.type}-${uf.codePoint.toString(16)}`,
      severity: severityMap[uf.type],
      message: `[Social Eng] Unicode ${uf.type} character detected: ${uf.charName}`,
      file: filePath,
      line: uf.line,
      column: uf.column,
      mitreTechniques: uf.type === 'bidi' ? ['T1036'] : ['T1564', 'T1027'],
      remediation: getRemediationForType(uf.type),
      metadata: {
        pluginId,
        category: uf.type === 'bidi' || uf.type === 'combining' || uf.type === 'tag_char'
          ? 'trojan_source'
          : 'unicode_tricks',
        scanner: 'unicode-scanner',
        codePoint: `U+${uf.codePoint.toString(16).toUpperCase().padStart(4, '0')}`,
        context: uf.context,
      },
    };
  });
}

// ─── Utility Functions ──────────────────────────────────────────

/**
 * Extract context around a character position (up to 40 chars each side).
 */
function extractContext(line: string, col: number): string {
  const start = Math.max(0, col - 20);
  const end = Math.min(line.length, col + 20);
  return line.slice(start, end);
}

/**
 * Get a human-readable name for a bidirectional control character.
 */
function getBidiCharName(cp: number): string {
  const names: Record<number, string> = {
    0x200E: 'LEFT-TO-RIGHT MARK',
    0x200F: 'RIGHT-TO-LEFT MARK',
    0x202A: 'LEFT-TO-RIGHT EMBEDDING',
    0x202B: 'RIGHT-TO-LEFT EMBEDDING',
    0x202C: 'POP DIRECTIONAL FORMATTING',
    0x202D: 'LEFT-TO-RIGHT OVERRIDE',
    0x202E: 'RIGHT-TO-LEFT OVERRIDE',
    0x2066: 'LEFT-TO-RIGHT ISOLATE',
    0x2067: 'RIGHT-TO-LEFT ISOLATE',
    0x2068: 'FIRST STRONG ISOLATE',
    0x2069: 'POP DIRECTIONAL ISOLATE',
  };
  return names[cp] ?? `BIDI U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
}

/**
 * Get a human-readable name for a zero-width character.
 */
function getZeroWidthCharName(cp: number): string {
  const names: Record<number, string> = {
    0x200B: 'ZERO WIDTH SPACE',
    0x200C: 'ZERO WIDTH NON-JOINER',
    0x200D: 'ZERO WIDTH JOINER',
    0x2060: 'WORD JOINER',
    0x2061: 'FUNCTION APPLICATION',
    0x2062: 'INVISIBLE TIMES',
    0x2063: 'INVISIBLE SEPARATOR',
    0x2064: 'INVISIBLE PLUS',
    0xFEFF: 'ZERO WIDTH NO-BREAK SPACE (BOM)',
    0x00AD: 'SOFT HYPHEN',
  };
  return names[cp] ?? `ZERO-WIDTH U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
}

/**
 * Get remediation advice for a Unicode finding type.
 */
function getRemediationForType(type: UnicodeFinding['type']): string {
  switch (type) {
    case 'bidi':
      return 'Remove bidirectional control characters. These can make code display differently from what is executed (Trojan Source CVE-2021-42574).';
    case 'homoglyph':
      return 'Replace homoglyph characters with their ASCII equivalents. Mixed-script identifiers can shadow legitimate variables.';
    case 'zero_width':
      return 'Remove zero-width characters. These invisible characters can hide data or create invisible identifier differences.';
    case 'combining':
      return 'Remove excessive combining diacritical marks that obscure underlying text content.';
    case 'tag_char':
      return 'Remove Unicode Tag characters. The Tags block (U+E0001-E007F) can encode hidden ASCII text.';
  }
}
