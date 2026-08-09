import { describe, expect, it } from 'vitest';
import { shouldReviewInteractively } from '../../../src/presentation/cli/commands/ScanCommand.js';

describe('ScanCommand interaction policy', () => {
  it('reviews only a normal foreground CLI scan', () => {
    expect(shouldReviewInteractively({ quiet: false, json: false, source: 'cli' })).toBe(true);
  });

  it.each([
    { quiet: true, json: false, source: 'cli' },
    { quiet: false, json: true, source: 'cli' },
    { quiet: false, json: false, source: 'git' },
    { quiet: false, json: false, source: 'git-post-checkout' },
  ])('never prompts for automated scan %#', (input) => {
    expect(shouldReviewInteractively(input)).toBe(false);
  });
});
