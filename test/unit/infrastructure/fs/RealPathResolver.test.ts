import { describe, expect, it } from 'vitest';
import { AbsolutePath } from '../../../../src/domain/value-objects/AbsolutePath.js';
import { RealPathResolver } from '../../../../src/infrastructure/fs/RealPathResolver.js';

describe('RealPathResolver', () => {
  it('terminates at a Windows drive root when every component is missing', () => {
    const attempts: string[] = [];
    const resolver = new RealPathResolver((path) => {
      attempts.push(path);
      if (attempts.length > 10) return 'Z:/infinite-loop-sentinel';
      throw new Error('ENOENT');
    });
    const input = AbsolutePath.of('C:/Users/dev/missing/file.txt');

    expect(resolver.resolve(input)).toEqual(input);
    expect(attempts).toEqual([
      'C:/users/dev/missing/file.txt',
      'C:/users/dev/missing',
      'C:/users/dev',
      'C:/users',
      'C:/',
    ]);
  });

  it('reattaches the missing tail to a resolved Windows ancestor', () => {
    const resolver = new RealPathResolver((path) => {
      if (path === 'C:/users/dev') return 'D:/Canonical/dev';
      throw new Error('ENOENT');
    });
    expect(resolver.resolve(AbsolutePath.of('C:/Users/dev/new/cache'))).toEqual(
      AbsolutePath.of('D:/Canonical/dev/new/cache'),
    );
  });
});
