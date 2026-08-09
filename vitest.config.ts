import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'unit',
          include: ['test/unit/**/*.test.ts'],
          environment: 'node',
        },
      },
      {
        test: {
          name: 'integration',
          include: ['test/integration/**/*.test.ts'],
          environment: 'node',
          testTimeout: 20_000,
        },
      },
      {
        test: {
          name: 'sandbox',
          include: ['test/sandbox/**/*.test.ts'],
          environment: 'node',
          testTimeout: 60_000,
          // Sandbox tests spawn real isolated processes; keep them serial so
          // measurements and canary files do not interfere with each other.
          fileParallelism: false,
        },
      },
      {
        test: {
          name: 'e2e',
          include: ['test/e2e/**/*.test.ts'],
          environment: 'node',
          testTimeout: 120_000,
          fileParallelism: false,
        },
      },
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: [
        // Barrels and type-only modules: interfaces have no behaviour to cover,
        // and counting them as 0% would report a number about nothing.
        'src/**/index.ts',
        'src/application/ports/**',
        // Exercised by the sandbox and e2e suites, which run separately because
        // they spawn real processes and depend on the host platform.
        'src/presentation/**',
        'src/composition/**',
        'src/infrastructure/adapters.ts',
        'src/infrastructure/sandbox/SeatbeltRunner.ts',
        'src/infrastructure/sandbox/BubblewrapRunner.ts',
        'src/infrastructure/sandbox/WindowsSandboxRunner.ts',
        'src/infrastructure/sandbox/NoopRunner.ts',
        'src/infrastructure/sandbox/SandboxRunnerFactory.ts',
        'src/infrastructure/network/NodeDestinationBroker.ts',
      ],
      thresholds: {
        lines: 85,
        branches: 85,
        functions: 85,
        statements: 85,
        'src/domain/**': {
          lines: 100,
          branches: 95,
          functions: 100,
          statements: 100,
        },
        'src/application/**': {
          lines: 95,
          branches: 90,
          functions: 95,
          statements: 95,
        },
      },
    },
  },
});
