/**
 * WIGTN-SHIELD Integration: Gap Analyzer
 *
 * Analyzes gaps between SPEAR attack payloads and SHIELD detection signatures.
 * Identifies which attacks are detected, which are missed, and generates
 * coverage reports to improve defensive capabilities.
 *
 * The analyzer works by:
 *   1. Taking a set of SPEAR attack payloads (strings)
 *   2. Testing each against SHIELD detection signatures (regex patterns)
 *   3. Classifying results as detected, missed, or partially detected
 *   4. Computing coverage metrics per category and overall
 *   5. Generating actionable gap reports
 */

import type { Severity } from '@wigtn/shared';
import { DISTILLATION_SIGNATURES, type DetectionSignature } from './signatures.js';

// ─── Gap Analysis Types ────────────────────────────────────────

export interface AttackPayload {
  id: string;
  payload: string;
  category: string;
  severity: string;
  technique: string;
}

export interface DetectionResult {
  payload: AttackPayload;
  detected: boolean;
  matchedSignatures: string[];
  confidenceScore: number;
}

export interface CategoryCoverage {
  category: string;
  totalPayloads: number;
  detectedPayloads: number;
  missedPayloads: number;
  coveragePercent: number;
  missedPayloadIds: string[];
  averageConfidence: number;
}

export interface GapReport {
  timestamp: string;
  totalPayloads: number;
  totalDetected: number;
  totalMissed: number;
  overallCoverage: number;
  categoryCoverage: CategoryCoverage[];
  criticalGaps: DetectionResult[];
  recommendations: string[];
  signatureEffectiveness: SignatureEffectiveness[];
}

export interface SignatureEffectiveness {
  signatureId: string;
  signatureName: string;
  totalMatches: number;
  uniquePayloadsDetected: number;
  categories: string[];
  falsePositiveRate: string;
}

// ─── Gap Analyzer ──────────────────────────────────────────────

/**
 * GapAnalyzer: Compares SPEAR attack payloads against SHIELD signatures.
 *
 * Usage:
 *   const analyzer = new GapAnalyzer();
 *   analyzer.addPayloads(attackPayloads);
 *   analyzer.addSignatures(customSignatures); // optional
 *   const report = analyzer.analyze();
 */
export class GapAnalyzer {
  private payloads: AttackPayload[] = [];
  private signatures: DetectionSignature[] = [...DISTILLATION_SIGNATURES];

  /**
   * Add attack payloads to the analyzer.
   */
  addPayloads(payloads: AttackPayload[]): void {
    this.payloads.push(...payloads);
  }

  /**
   * Add custom detection signatures (in addition to built-in ones).
   */
  addSignatures(signatures: DetectionSignature[]): void {
    this.signatures.push(...signatures);
  }

  /**
   * Clear all payloads and reset to built-in signatures only.
   */
  reset(): void {
    this.payloads = [];
    this.signatures = [...DISTILLATION_SIGNATURES];
  }

  /**
   * Run the gap analysis and produce a comprehensive report.
   */
  analyze(): GapReport {
    const results = this.testPayloads();
    const categoryCoverage = this.computeCategoryCoverage(results);
    const signatureEffectiveness = this.computeSignatureEffectiveness(results);
    const criticalGaps = this.identifyCriticalGaps(results);
    const recommendations = this.generateRecommendations(categoryCoverage, criticalGaps);

    const totalDetected = results.filter((r) => r.detected).length;
    const totalMissed = results.filter((r) => !r.detected).length;

    return {
      timestamp: new Date().toISOString(),
      totalPayloads: this.payloads.length,
      totalDetected,
      totalMissed,
      overallCoverage: this.payloads.length > 0
        ? (totalDetected / this.payloads.length) * 100
        : 0,
      categoryCoverage,
      criticalGaps,
      recommendations,
      signatureEffectiveness,
    };
  }

  /**
   * Test each payload against all signatures.
   */
  private testPayloads(): DetectionResult[] {
    return this.payloads.map((payload) => {
      const matchedSignatures: string[] = [];
      let maxConfidence = 0;

      for (const signature of this.signatures) {
        for (const pattern of signature.patterns) {
          if (pattern.test(payload.payload)) {
            if (!matchedSignatures.includes(signature.id)) {
              matchedSignatures.push(signature.id);
            }
            // Confidence based on pattern specificity and false positive rate
            const confidence = this.computeConfidence(signature);
            if (confidence > maxConfidence) {
              maxConfidence = confidence;
            }
            break; // One pattern match per signature is sufficient
          }
        }
      }

      return {
        payload,
        detected: matchedSignatures.length > 0,
        matchedSignatures,
        confidenceScore: maxConfidence,
      };
    });
  }

  /**
   * Compute detection confidence based on signature properties.
   */
  private computeConfidence(signature: DetectionSignature): number {
    const fpMultiplier: Record<string, number> = {
      low: 0.95,
      medium: 0.75,
      high: 0.50,
    };

    const severityMultiplier: Record<Severity, number> = {
      critical: 1.0,
      high: 0.9,
      medium: 0.8,
      low: 0.7,
      info: 0.5,
    };

    const fpScore = fpMultiplier[signature.falsePositiveRate] ?? 0.5;
    const sevScore = severityMultiplier[signature.severity] ?? 0.5;

    return fpScore * sevScore;
  }

  /**
   * Compute coverage metrics per attack category.
   */
  private computeCategoryCoverage(results: DetectionResult[]): CategoryCoverage[] {
    const categoryMap = new Map<string, DetectionResult[]>();

    for (const result of results) {
      const cat = result.payload.category;
      if (!categoryMap.has(cat)) {
        categoryMap.set(cat, []);
      }
      categoryMap.get(cat)!.push(result);
    }

    const coverages: CategoryCoverage[] = [];

    for (const [category, categoryResults] of categoryMap) {
      const detected = categoryResults.filter((r) => r.detected);
      const missed = categoryResults.filter((r) => !r.detected);
      const avgConfidence =
        detected.length > 0
          ? detected.reduce((sum, r) => sum + r.confidenceScore, 0) / detected.length
          : 0;

      coverages.push({
        category,
        totalPayloads: categoryResults.length,
        detectedPayloads: detected.length,
        missedPayloads: missed.length,
        coveragePercent: categoryResults.length > 0
          ? (detected.length / categoryResults.length) * 100
          : 0,
        missedPayloadIds: missed.map((r) => r.payload.id),
        averageConfidence: Math.round(avgConfidence * 100) / 100,
      });
    }

    // Sort by coverage (lowest first) to highlight gaps
    coverages.sort((a, b) => a.coveragePercent - b.coveragePercent);

    return coverages;
  }

  /**
   * Compute how effective each signature is across all payloads.
   */
  private computeSignatureEffectiveness(results: DetectionResult[]): SignatureEffectiveness[] {
    const sigStats = new Map<string, {
      name: string;
      totalMatches: number;
      uniquePayloads: Set<string>;
      categories: Set<string>;
      falsePositiveRate: string;
    }>();

    // Initialize from signatures
    for (const sig of this.signatures) {
      sigStats.set(sig.id, {
        name: sig.name,
        totalMatches: 0,
        uniquePayloads: new Set(),
        categories: new Set(),
        falsePositiveRate: sig.falsePositiveRate,
      });
    }

    // Count matches
    for (const result of results) {
      for (const sigId of result.matchedSignatures) {
        const stats = sigStats.get(sigId);
        if (stats) {
          stats.totalMatches++;
          stats.uniquePayloads.add(result.payload.id);
          stats.categories.add(result.payload.category);
        }
      }
    }

    return Array.from(sigStats.entries()).map(([id, stats]) => ({
      signatureId: id,
      signatureName: stats.name,
      totalMatches: stats.totalMatches,
      uniquePayloadsDetected: stats.uniquePayloads.size,
      categories: Array.from(stats.categories),
      falsePositiveRate: stats.falsePositiveRate,
    }));
  }

  /**
   * Identify critical gaps: undetected payloads with high/critical severity.
   */
  private identifyCriticalGaps(results: DetectionResult[]): DetectionResult[] {
    return results
      .filter((r) => !r.detected && (r.payload.severity === 'critical' || r.payload.severity === 'high'))
      .sort((a, b) => {
        const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
        return (severityOrder[a.payload.severity] ?? 4) - (severityOrder[b.payload.severity] ?? 4);
      });
  }

  /**
   * Generate actionable recommendations based on coverage gaps.
   */
  private generateRecommendations(
    coverage: CategoryCoverage[],
    criticalGaps: DetectionResult[],
  ): string[] {
    const recommendations: string[] = [];

    // Category-level recommendations
    for (const cat of coverage) {
      if (cat.coveragePercent < 50) {
        recommendations.push(
          `CRITICAL: ${cat.category} has only ${cat.coveragePercent.toFixed(1)}% coverage. ` +
          `${cat.missedPayloads} of ${cat.totalPayloads} attack payloads are undetected. ` +
          `Add new detection signatures for this category.`,
        );
      } else if (cat.coveragePercent < 80) {
        recommendations.push(
          `WARNING: ${cat.category} coverage is at ${cat.coveragePercent.toFixed(1)}%. ` +
          `${cat.missedPayloads} payloads remain undetected. Consider expanding pattern coverage.`,
        );
      }
    }

    // Critical gap recommendations
    if (criticalGaps.length > 0) {
      const criticalCount = criticalGaps.filter((g) => g.payload.severity === 'critical').length;
      const highCount = criticalGaps.filter((g) => g.payload.severity === 'high').length;

      if (criticalCount > 0) {
        recommendations.push(
          `URGENT: ${criticalCount} critical-severity attack payloads are completely undetected. ` +
          `These represent the highest-risk distillation attacks.`,
        );
      }

      if (highCount > 0) {
        recommendations.push(
          `HIGH PRIORITY: ${highCount} high-severity attack payloads bypass all current signatures.`,
        );
      }
    }

    // Overall recommendations
    const overallCoverage = coverage.length > 0
      ? coverage.reduce((sum, c) => sum + c.coveragePercent, 0) / coverage.length
      : 0;

    if (overallCoverage >= 90) {
      recommendations.push(
        'Overall coverage is strong (>90%). Focus on reducing false positive rates and improving detection confidence.',
      );
    } else if (overallCoverage >= 70) {
      recommendations.push(
        'Overall coverage is moderate (70-90%). Prioritize closing gaps in lowest-coverage categories.',
      );
    } else {
      recommendations.push(
        'Overall coverage is insufficient (<70%). A comprehensive signature update is needed across all categories.',
      );
    }

    return recommendations;
  }
}
