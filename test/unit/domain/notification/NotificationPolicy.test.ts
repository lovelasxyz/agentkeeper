import { describe, expect, it } from 'vitest';

import {
  NotificationBudget,
  NotificationPolicy,
  suppressNotification,
} from '../../../../src/domain/notification/NotificationPolicy.js';

/**
 * The notification policy is a domain object: rate, cooldown and fairness
 * decided without a file system, so the use case only orchestrates the answer.
 */
describe('NotificationPolicy', () => {
  it('rejects limits that are not positive integers', () => {
    expect(() => NotificationPolicy.create({ maxPerWindow: 0, windowMilliseconds: 1000, duplicateCooldownMilliseconds: 1000 })).toThrow('positive integers');
    expect(() => NotificationPolicy.create({ maxPerWindow: 2.5, windowMilliseconds: 1000, duplicateCooldownMilliseconds: 1000 })).toThrow('positive integers');
    expect(() => NotificationPolicy.create({ maxPerWindow: 5, windowMilliseconds: 0, duplicateCooldownMilliseconds: 1000 })).toThrow('positive integers');
    expect(() => NotificationPolicy.create({ maxPerWindow: 5, windowMilliseconds: 1000, duplicateCooldownMilliseconds: 0 })).toThrow('positive integers');
  });
});

describe('NotificationBudget', () => {
  const policy = NotificationPolicy.create({
    maxPerWindow: 2,
    windowMilliseconds: 60_000,
    duplicateCooldownMilliseconds: 15 * 60_000,
  });

  it('suppresses the same decision key inside its cooldown window', () => {
    const budget = new NotificationBudget(policy);
    const t0 = new Date('2026-08-13T10:00:00Z');

    expect(budget.claim('key-a', t0)).toBeNull();
    expect(budget.claim('key-a', new Date(t0.getTime() + 60_000))).toBe('duplicate');
    // A duplicate does not spend window budget: a repeated finding must not
    // crowd out a new one.
    expect(budget.claim('key-b', new Date(t0.getTime() + 60_000))).toBeNull();
    expect(budget.claim('key-c', new Date(t0.getTime() + 60_000))).toBeNull();
  });

  it('rate-limits inside the window and recovers after it', () => {
    const budget = new NotificationBudget(policy);
    const t0 = new Date('2026-08-13T10:00:00Z');

    expect(budget.claim('a', t0)).toBeNull();
    expect(budget.claim('b', t0)).toBeNull();
    expect(budget.claim('c', t0)).toBe('rate-limit');
    // A refused claim did not count as sent.
    expect(budget.claim('a', new Date(t0.getTime() + 16 * 60_000))).toBeNull();
    expect(budget.claim('c', new Date(t0.getTime() + 61_000))).toBeNull();
  });

  it('bounds memory against a stream of unique keys', () => {
    const budget = new NotificationBudget(
      NotificationPolicy.create({
        maxPerWindow: 10_000,
        windowMilliseconds: 3_600_000,
        duplicateCooldownMilliseconds: 3_600_000,
      }),
    );
    const t0 = new Date('2026-08-13T10:00:00Z');
    for (let index = 0; index < 600; index += 1) {
      expect(budget.claim(`key-${index}`, t0)).toBeNull();
    }
    // The oldest keys were evicted first: fairness against a hostile stream.
    expect(budget.claim('key-0', t0)).toBeNull();
    expect(budget.claim('key-599', t0)).toBe('duplicate');
  });
});

describe('suppressNotification', () => {
  const policy = NotificationPolicy.STANDARD;

  it('pauses before anything else is considered', () => {
    const budget = new NotificationBudget(policy);
    expect(
      suppressNotification({ paused: true, approvedHigh: false, budget, decisionKey: 'k', at: new Date() }),
    ).toBe('paused');
  });

  it('suppresses an already-approved high-severity finding without spending budget', () => {
    const budget = new NotificationBudget(policy);
    const at = new Date();
    expect(
      suppressNotification({ paused: false, approvedHigh: true, budget, decisionKey: 'k', at }),
    ).toBe('approved');
    // The claim never reached the budget, so a different finding still sends.
    expect(budget.claim('other', at)).toBeNull();
  });

  it('delegates to the budget for an ordinary finding', () => {
    const budget = new NotificationBudget(policy);
    const at = new Date('2026-08-13T10:00:00Z');
    expect(
      suppressNotification({ paused: false, approvedHigh: false, budget, decisionKey: 'k', at }),
    ).toBeNull();
    expect(
      suppressNotification({ paused: false, approvedHigh: false, budget, decisionKey: 'k', at }),
    ).toBe('duplicate');
  });
});
