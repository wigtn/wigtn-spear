/**
 * Git Diff Parser -- Extracts added lines from unified diff output.
 *
 * Parses the output of `git show <hash>` or `git diff` into structured
 * data that the scanner can process. Only added lines (prefixed with '+')
 * are extracted, since we are looking for secrets that were introduced
 * (not removed).
 *
 * Handles:
 *   - Multiple files in a single diff
 *   - Rename tracking (--- a/old_path, +++ b/new_path)
 *   - Binary file markers (skipped)
 *   - Deleted files (skipped -- no added content)
 *   - Hunk headers (@@ -X,Y +A,B @@) for accurate line numbers
 */

/** A single added line extracted from a diff */
export interface DiffAddition {
  /** The content of the added line (without the leading '+') */
  content: string;
  /** 1-based line number in the new version of the file */
  line: number;
}

/** A parsed file from a diff, containing only its added lines */
export interface DiffFile {
  /** File path (from the +++ header, relative to repo root) */
  file: string;
  /** All added lines in this file's diff hunks */
  additions: DiffAddition[];
}

/**
 * Parse unified diff output into structured DiffFile entries.
 *
 * @param diffContent - Raw unified diff string (from git show / git diff).
 * @returns Array of DiffFile objects, one per modified file. Files with
 *   no additions (pure deletions, binary files) are excluded.
 */
export function parseDiff(diffContent: string): DiffFile[] {
  if (!diffContent || diffContent.length === 0) {
    return [];
  }

  const results: DiffFile[] = [];
  const lines = diffContent.split('\n');

  let currentFile: string | null = null;
  let currentAdditions: DiffAddition[] = [];
  let currentNewLine = 0; // Tracks the current line number in the new file
  let inBinaryFile = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;

    // Detect new file diff header: "diff --git a/path b/path"
    if (line.startsWith('diff --git ')) {
      // Flush previous file if it had additions
      if (currentFile !== null && currentAdditions.length > 0) {
        results.push({ file: currentFile, additions: currentAdditions });
      }

      // Reset state for new file
      currentFile = null;
      currentAdditions = [];
      currentNewLine = 0;
      inBinaryFile = false;
      continue;
    }

    // Detect binary file marker
    if (line.startsWith('Binary files ') || line.startsWith('GIT binary patch')) {
      inBinaryFile = true;
      continue;
    }

    // Skip binary files entirely
    if (inBinaryFile) {
      continue;
    }

    // Parse the +++ header to get the new file path
    // Format: "+++ b/path/to/file" or "+++ /dev/null" (for deleted files)
    if (line.startsWith('+++ ')) {
      const filePath = line.slice(4);

      if (filePath === '/dev/null') {
        // File was deleted -- no additions to extract
        currentFile = null;
        continue;
      }

      // Strip the "b/" prefix (standard git diff format)
      if (filePath.startsWith('b/')) {
        currentFile = filePath.slice(2);
      } else {
        currentFile = filePath;
      }
      continue;
    }

    // Skip --- header (old file path -- not needed for additions)
    if (line.startsWith('--- ')) {
      continue;
    }

    // Parse hunk header: "@@ -oldStart,oldCount +newStart,newCount @@"
    if (line.startsWith('@@ ')) {
      const hunkMatch = line.match(/@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      if (hunkMatch) {
        currentNewLine = parseInt(hunkMatch[1]!, 10);
      }
      continue;
    }

    // Skip if we haven't identified a file yet
    if (currentFile === null) {
      continue;
    }

    // Parse content lines within a hunk
    if (line.startsWith('+')) {
      // Added line: extract content (strip the leading '+')
      const content = line.slice(1);

      // Skip empty additions (just a '+' with nothing after)
      if (content.length > 0) {
        currentAdditions.push({
          content,
          line: currentNewLine,
        });
      }
      currentNewLine++;
    } else if (line.startsWith('-')) {
      // Deleted line: does not affect new file line numbers
      // Do not increment currentNewLine
    } else if (line.startsWith(' ')) {
      // Context line: present in both old and new
      currentNewLine++;
    } else if (line === '\\ No newline at end of file') {
      // Git metadata line; skip
    } else {
      // Unknown line type within a hunk; skip but advance line counter
      // (this handles edge cases with unusual diff formats)
    }
  }

  // Flush the last file
  if (currentFile !== null && currentAdditions.length > 0) {
    results.push({ file: currentFile, additions: currentAdditions });
  }

  return results;
}

/**
 * Extract all added content from a diff as a single concatenated string.
 *
 * Useful for feeding the entire diff's additions into the Aho-Corasick
 * pre-filter as a single pass before doing line-level matching.
 *
 * @param diffContent - Raw unified diff string.
 * @returns Concatenated content of all added lines, joined by newlines.
 */
export function extractAddedContent(diffContent: string): string {
  const files = parseDiff(diffContent);
  const allAdditions: string[] = [];

  for (const file of files) {
    for (const addition of file.additions) {
      allAdditions.push(addition.content);
    }
  }

  return allAdditions.join('\n');
}
