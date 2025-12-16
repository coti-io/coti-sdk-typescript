module.exports = {
    transform: {'^.+\\.ts?$': 'ts-jest'},
    testEnvironment: 'node',
    testRegex: '/tests/(unit|integration|e2e)/.*\\.(test|spec)?\\.(ts|tsx)$',
    moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
    setupFiles: ['<rootDir>/tests/setup.ts'],
    collectCoverage: true,
    coverageReporters: ['text', 'json-summary'],
    coveragePathIgnorePatterns: [
        '/node_modules/',
        '/dist/',
        '/tests/'
    ],
    reporters: [
        'default',
        [
            'jest-html-reporters',
            {
                publicPath: './test-report',
                filename: 'report.html',
                openReport: false,
                expand: true,
                hideIcon: false,
                pageTitle: 'COTI SDK Test Report',
                inlineSource: false,
            }
        ],
        [
            'jest-junit',
            {
                outputDirectory: '.',
                outputName: 'test-results.xml',
                suiteName: 'COTI SDK Tests',
                classNameTemplate: '{classname}',
                titleTemplate: '{title}',
                ancestorSeparator: ' › ',
                usePathForSuiteName: 'true'
            }
        ]
    ],
    testResultsProcessor: 'jest-junit'
};