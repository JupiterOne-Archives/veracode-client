module.exports = {
  testMatch: [
    '<rootDir>/**/*.test.js'
  ],
  collectCoverageFrom: ['src/**/*.js'],
  testEnvironment: 'node',
  clearMocks: true,
  collectCoverage: true,
  coverageThreshold: {
    global: {
      statements: 60,
      branches: 80,
      functions: 50,
      lines: 60
    }
  }
};
