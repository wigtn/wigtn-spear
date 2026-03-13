/**
 * @wigtn/rules-engine -- YAML-based security rule parser and loader
 *
 * Provides:
 *   - loadRules()    -- recursively loads and validates YAML rule files
 *   - validateRule() -- validates a single raw object against the Rule schema
 *
 * Usage:
 *   import { loadRules } from '@wigtn/rules-engine';
 *
 *   const rules = await loadRules('./rules/', logger);
 *   // rules: Rule[] -- only valid, well-formed rules
 */

export { loadRules } from './loader.js';
export { validateRule, type ValidationResult, type ValidationError } from './validator.js';
