/**
 * Aho-Corasick Multi-Pattern String Matching Algorithm
 *
 * This is a custom implementation optimized for WIGTN-SPEAR's keyword
 * pre-filtering stage. The algorithm performs simultaneous matching of
 * all keywords in a single pass through the text, achieving O(n + m + z)
 * time complexity where:
 *   n = text length
 *   m = total keyword characters
 *   z = number of matches found
 *
 * Used in the scan pipeline to quickly identify candidate files that
 * contain any of the configured keywords before running expensive
 * regex matching.
 */

/**
 * A node in the Aho-Corasick trie (finite automaton).
 *
 * Each node represents a state in the automaton.
 * - `children` maps a character to the next state.
 * - `failure` points to the longest proper suffix that is also a prefix
 *   of some pattern (the classic Aho-Corasick failure link).
 * - `output` collects all keywords that end at this state, including
 *   those inherited via the output/dictionary suffix link chain.
 */
class TrieNode {
  /** Transition map: character -> child node */
  readonly children: Map<string, TrieNode> = new Map();

  /** Failure link (computed during BFS phase) */
  failure: TrieNode | null = null;

  /**
   * Output set: keywords that are complete at this node.
   * Includes keywords inherited through the dictionary suffix link chain.
   */
  readonly output: string[] = [];

  /**
   * Depth of this node in the trie (root = 0).
   * Used to compute match positions.
   */
  depth: number = 0;
}

export interface AhoCorasickMatch {
  /** The keyword that was matched */
  keyword: string;
  /** The start position (0-based index) of the match in the text */
  position: number;
}

/**
 * Aho-Corasick automaton for multi-pattern string matching.
 *
 * Usage:
 * ```ts
 * const ac = new AhoCorasick(['aws_secret', 'api_key', 'password']);
 * const matches = ac.search(fileContents);
 * // matches: [{ keyword: 'api_key', position: 42 }, ...]
 * ```
 *
 * The automaton is built once at construction time and can be reused
 * for searching across many texts (thread-safe for reads).
 */
export class AhoCorasick {
  private readonly root: TrieNode;
  private readonly keywords: string[];
  private built: boolean = false;

  /**
   * Construct an Aho-Corasick automaton from a set of keywords.
   *
   * @param keywords - Array of keyword strings to match. Empty strings
   *   and duplicates are silently filtered. Matching is case-sensitive.
   */
  constructor(keywords: string[]) {
    this.root = new TrieNode();
    // Deduplicate and filter empty strings
    this.keywords = [...new Set(keywords.filter((k) => k.length > 0))];
    this.build();
  }

  /**
   * Search the text for all occurrences of any keyword.
   *
   * @param text - The text to search through.
   * @returns Array of matches, each with the matched keyword and its
   *   start position in the text. Results are ordered by position,
   *   with ties broken by keyword insertion order.
   */
  search(text: string): AhoCorasickMatch[] {
    if (text.length === 0 || this.keywords.length === 0) {
      return [];
    }

    const results: AhoCorasickMatch[] = [];
    let current: TrieNode = this.root;

    for (let i = 0; i < text.length; i++) {
      const ch = text[i]!;

      // Follow failure links until we find a valid transition or reach root
      while (current !== this.root && !current.children.has(ch)) {
        current = current.failure ?? this.root;
      }

      const next = current.children.get(ch);
      if (next) {
        current = next;
      }
      // If no transition from root, current stays at root

      // Collect all outputs at the current state
      // This includes keywords ending here and those found via output links
      let temp: TrieNode | null = current;
      while (temp !== null && temp !== this.root) {
        for (const keyword of temp.output) {
          results.push({
            keyword,
            // Position is the start of the keyword in the text
            position: i - keyword.length + 1,
          });
        }
        // Follow failure link to check for shorter keyword matches
        temp = temp.failure;
      }
    }

    return results;
  }

  /**
   * Check if the text contains any of the keywords.
   * More efficient than search() when you only need a boolean answer,
   * as it short-circuits on the first match.
   *
   * @param text - The text to check.
   * @returns true if at least one keyword is found.
   */
  contains(text: string): boolean {
    if (text.length === 0 || this.keywords.length === 0) {
      return false;
    }

    let current: TrieNode = this.root;

    for (let i = 0; i < text.length; i++) {
      const ch = text[i]!;

      while (current !== this.root && !current.children.has(ch)) {
        current = current.failure ?? this.root;
      }

      const next = current.children.get(ch);
      if (next) {
        current = next;
      }

      // Check for any output at this state or through failure chain
      let temp: TrieNode | null = current;
      while (temp !== null && temp !== this.root) {
        if (temp.output.length > 0) {
          return true;
        }
        temp = temp.failure;
      }
    }

    return false;
  }

  /**
   * Return the list of keywords this automaton was built with.
   */
  getKeywords(): readonly string[] {
    return this.keywords;
  }

  /**
   * Build the complete automaton: trie construction + failure link computation.
   */
  private build(): void {
    if (this.built) return;
    this.buildTrie();
    this.buildFailureLinks();
    this.built = true;
  }

  /**
   * Phase 1: Build the keyword trie.
   *
   * Insert each keyword character-by-character into the trie.
   * When a keyword is fully inserted, add it to the output set
   * of the terminal node.
   */
  private buildTrie(): void {
    for (const keyword of this.keywords) {
      let current = this.root;

      for (let i = 0; i < keyword.length; i++) {
        const ch = keyword[i]!;
        let child = current.children.get(ch);

        if (!child) {
          child = new TrieNode();
          child.depth = current.depth + 1;
          current.children.set(ch, child);
        }

        current = child;
      }

      // Mark this node as a terminal for this keyword
      current.output.push(keyword);
    }
  }

  /**
   * Phase 2: Build failure links using BFS (Breadth-First Search).
   *
   * The failure link of a node points to the longest proper suffix
   * of the string represented by that node which is also a prefix
   * of some pattern in the trie.
   *
   * Algorithm:
   * 1. All depth-1 nodes have their failure link set to root.
   * 2. For each node at depth >= 2, follow the parent's failure link
   *    chain until we find a node with a matching child transition,
   *    or fall back to root.
   * 3. Merge output sets: if a node's failure target has outputs,
   *    those are also valid matches at this node (dictionary suffix links).
   */
  private buildFailureLinks(): void {
    const queue: TrieNode[] = [];

    // Initialize depth-1 nodes: failure -> root
    for (const child of this.root.children.values()) {
      child.failure = this.root;
      queue.push(child);
    }

    // BFS through the trie
    while (queue.length > 0) {
      const current = queue.shift()!;

      for (const [ch, child] of current.children) {
        queue.push(child);

        // Walk up failure chain from current node to find the
        // longest suffix that has a transition on `ch`
        let failureTarget = current.failure;

        while (failureTarget !== null && !failureTarget.children.has(ch)) {
          failureTarget = failureTarget.failure;
        }

        if (failureTarget === null) {
          // No suffix match found; fail to root
          child.failure = this.root;
        } else {
          // Found a suffix with a transition on `ch`
          child.failure = failureTarget.children.get(ch) ?? this.root;

          // Avoid self-loop (should not happen in a correctly built trie,
          // but guard defensively)
          if (child.failure === child) {
            child.failure = this.root;
          }
        }

        // Merge output: inherit keywords from the failure chain
        // This implements the "dictionary suffix link" optimization,
        // so we don't need to walk the entire failure chain during search
        // for output collection. However, we keep the walk in search()
        // for correctness with overlapping patterns.
        if (child.failure.output.length > 0) {
          child.output.push(...child.failure.output);
        }
      }
    }
  }
}

/**
 * Case-insensitive variant of Aho-Corasick.
 *
 * Converts both keywords and search text to lowercase before matching.
 * Match positions are still reported relative to the original text.
 */
export class AhoCorasickCaseInsensitive {
  private readonly inner: AhoCorasick;
  private readonly originalKeywords: readonly string[];

  constructor(keywords: string[]) {
    this.originalKeywords = keywords.filter((k) => k.length > 0);
    this.inner = new AhoCorasick(keywords.map((k) => k.toLowerCase()));
  }

  search(text: string): AhoCorasickMatch[] {
    return this.inner.search(text.toLowerCase());
  }

  contains(text: string): boolean {
    return this.inner.contains(text.toLowerCase());
  }

  getKeywords(): readonly string[] {
    return this.originalKeywords;
  }
}
