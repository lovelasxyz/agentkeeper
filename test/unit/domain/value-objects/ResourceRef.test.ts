import { describe, expect, it } from 'vitest';
import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';
import { NetworkRule } from '../../../../src/domain/value-objects/NetworkRule.js';
import { ResourceRef } from '../../../../src/domain/value-objects/ResourceRef.js';

const p = (s: string): AbsolutePath => AbsolutePath.of(s);

describe('ResourceRef', () => {
  it('describes a whole subtree', () => {
    const ref = ResourceRef.subtree(p('/work'));
    expect(ref.scope).toBe('subtree');
    expect(ref.covers(p('/work/src/index.ts'))).toBe(true);
    expect(ref.covers(p('/work'))).toBe(true);
  });

  it('describes a single file', () => {
    const ref = ResourceRef.file(p('/Users/dev/.gitconfig'));
    expect(ref.scope).toBe('file');
    expect(ref.covers(p('/Users/dev/.gitconfig'))).toBe(true);
    expect(ref.covers(p('/Users/dev/.gitconfig/child'))).toBe(false);
  });

  it('does not cover an unrelated path', () => {
    expect(ResourceRef.subtree(p('/work')).covers(p('/other'))).toBe(false);
  });

  it('compares by value', () => {
    expect(ResourceRef.subtree(p('/a')).equals(ResourceRef.subtree(p('/a')))).toBe(true);
    expect(ResourceRef.subtree(p('/a')).equals(ResourceRef.file(p('/a')))).toBe(false);
  });

  it('reports when one ref subsumes another', () => {
    const parent = ResourceRef.subtree(p('/work'));
    expect(parent.subsumes(ResourceRef.file(p('/work/a.txt')))).toBe(true);
    expect(parent.subsumes(ResourceRef.subtree(p('/work/nested')))).toBe(true);
    expect(ResourceRef.file(p('/work/a.txt')).subsumes(parent)).toBe(false);
  });

  it('parses a user-facing resource reference', () => {
    const home = p('/Users/dev');
    expect(ResourceRef.parse('file:~/.gitconfig', home).equals(ResourceRef.file(p('/Users/dev/.gitconfig')))).toBe(true);
    expect(ResourceRef.parse('dir:~/projects', home).equals(ResourceRef.subtree(p('/Users/dev/projects')))).toBe(true);
  });

  it('rejects an unknown resource kind', () => {
    expect(() => ResourceRef.parse('socket:/tmp/x', p('/Users/dev'))).toThrow(/resource/i);
  });

  it('serialises back to its user-facing form', () => {
    const home = p('/Users/dev');
    expect(ResourceRef.file(p('/Users/dev/.gitconfig')).toResourceString(home)).toBe(
      'file:~/.gitconfig',
    );
    expect(ResourceRef.subtree(p('/opt/tools')).toResourceString(home)).toBe('dir:/opt/tools');
  });
});

describe('NetworkRule', () => {
  it('normalises an exact destination without widening it', () => {
    const rule = NetworkRule.destination('API.OpenAI.com.', 443);
    expect(rule.host).toBe('api.openai.com');
    expect(rule.port).toBe(443);
    expect(rule.matches('API.OPENAI.COM.', 443)).toBe(true);
    expect(rule.matches('evil-openai.com', 443)).toBe(false);
    expect(rule.matches('api.openai.com', 80)).toBe(false);
  });

  it('requires an explicit, label-boundary wildcard', () => {
    const rule = NetworkRule.destination('*.anthropic.com', 443);
    expect(rule.matches('api.anthropic.com', 443)).toBe(true);
    expect(rule.matches('deep.api.anthropic.com', 443)).toBe(true);
    expect(rule.matches('anthropic.com', 443)).toBe(false);
    expect(rule.matches('evilanthropic.com', 443)).toBe(false);
    expect(() => NetworkRule.destination('*anthropic.com', 443)).toThrow(/wildcard/i);
  });

  it('rejects authority syntax and ambiguous hostnames', () => {
    for (const host of ['', '.', 'https://api.openai.com', 'api.openai.com/path', 'user@host',
      '*.com', 'exa mple.com', '127.0.0.1']) {
      expect(() => NetworkRule.destination(host, 443), host).toThrow();
    }
  });

  it('describes outbound tcp on a port', () => {
    const rule = NetworkRule.tcp(443);
    expect(rule.protocol).toBe('tcp');
    expect(rule.port).toBe(443);
    expect(rule.host).toBe('any');
  });

  it('describes loopback access for local MCP servers', () => {
    const rule = NetworkRule.loopback();
    expect(rule.host).toBe('loopback');
    expect(rule.port).toBe('*');
    expect(rule.allowsLoopback).toBe(true);
    expect(rule.isExplicitDestination).toBe(false);
    expect(rule.matches('localhost', 3000)).toBe(true);
    expect(rule.matches('api.localhost.', 4317)).toBe(true);
    expect(rule.matches('127.0.0.1', 3000)).toBe(false);
  });

  it('fails closed when a candidate or configured hostname is malformed', () => {
    const exact = NetworkRule.destination('api.openai.com', 443);
    expect(exact.isExplicitDestination).toBe(true);
    expect(exact.matches('https://api.openai.com', 443)).toBe(false);
    expect(NetworkRule.udp(53).matches('anything.example', 53)).toBe(false);
    expect(NetworkRule.tcp(443).matches('anything.example', 443)).toBe(true);
    expect(NetworkRule.tcp(443).matches('anything.example', 80)).toBe(false);

    for (const host of [
      'münich.example',
      `${'a'.repeat(64)}.example`,
      `${'a'.repeat(250)}.com`,
      '-edge.example',
      'edge-.example',
    ]) {
      expect(() => NetworkRule.destination(host, 443), host).toThrow();
    }
  });

  it('rejects an out-of-range port', () => {
    expect(() => NetworkRule.tcp(0)).toThrow(/port/i);
    expect(() => NetworkRule.tcp(70_000)).toThrow(/port/i);
    expect(() => NetworkRule.tcp(1.5)).toThrow(/port/i);
    expect(NetworkRule.tcp('*').port).toBe('*');
  });

  it('compares by value', () => {
    expect(NetworkRule.tcp(443).equals(NetworkRule.tcp(443))).toBe(true);
    expect(NetworkRule.tcp(443).equals(NetworkRule.udp(443))).toBe(false);
  });

  it('renders a readable description', () => {
    expect(NetworkRule.tcp(443).toString()).toBe('tcp://*:443');
    expect(NetworkRule.udp('*').toString()).toBe('udp://*:*');
    expect(NetworkRule.loopback().toString()).toBe('ip://localhost:*');
    expect(NetworkRule.destination('api.openai.com', 443).toString()).toBe(
      'tcp://api.openai.com:443',
    );
  });
});
