import { defineConfig } from 'vitest/config'

export default defineConfig({
    test: {
        globals: true,
        environment: 'node',
        coverage: {
            provider: 'v8',
            reporter: ['text', 'json', 'html'],
            exclude: [
                'node_modules/',
                'test/',
                'dist/',
                '**/*.d.ts',
                '**/**.config.*',
                'docs/**',
                'scripts/**',
                '**/index.ts',
                'src/protobuf.ts',
                'src/public/crypto.ts',
                'src/public/errors.ts',
                'src/public/identity.ts',
                'src/public/logger.ts',
                'src/public/protobuf.ts',
                'src/public/session.ts',
                'src/public/signal.ts',
                'src/**/types.ts',
            ],
            thresholds: {
                statements: 100,
                branches: 100,
                functions: 100,
                lines: 100,
            },
        },
        include: ['test/**/*.test.ts'],
        exclude: ['node_modules', 'dist'],
        testTimeout: 30000,
    }
})
