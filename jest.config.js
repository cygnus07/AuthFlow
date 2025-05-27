// jest.config.js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
    setupFiles: ['<rootDir>/jest.setup.js'],
  moduleNameMapper: {  // Note the correct key is moduleNameMapper (not moduleNameMapping)
    '^@/(.*)$': '<rootDir>/src/$1'
  }
};