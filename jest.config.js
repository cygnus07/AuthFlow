// jest.config.js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  moduleNameMapper: {  // Note the correct key is moduleNameMapper (not moduleNameMapping)
    '^@/(.*)$': '<rootDir>/src/$1'
  }
};