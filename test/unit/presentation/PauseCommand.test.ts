import { describe, expect, it } from 'vitest';
import { parsePauseDuration } from '../../../src/presentation/cli/commands/PauseCommand.js';

describe('parsePauseDuration', () => {
  it('accepts bounded notification leases', () => {
    expect(parsePauseDuration('30m')).toBe(30 * 60_000);
    expect(parsePauseDuration('1h')).toBe(60 * 60_000);
    expect(parsePauseDuration('1d')).toBe(24 * 60 * 60_000);
    expect(parsePauseDuration('today')).toBe(8 * 60 * 60_000);
  });

  it('refuses malformed, zero, and overlong silence requests', () => {
    expect(parsePauseDuration('yes')).toBeNull();
    expect(parsePauseDuration('0m')).toBeNull();
    expect(parsePauseDuration('25h')).toBeNull();
    expect(parsePauseDuration('999999999999999999999d')).toBeNull();
  });
});
