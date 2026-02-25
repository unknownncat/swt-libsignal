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
            ]
        },
        include: ['test/**/*.test.ts'],
        exclude: ['node_modules', 'dist'],
        testTimeout: 30000,
    }
})
