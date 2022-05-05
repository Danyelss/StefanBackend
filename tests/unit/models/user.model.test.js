const faker = require('faker');
const { Machine } = require('../../../src/models');

describe('Machine model', () => {
  describe('Machine validation', () => {
    let newMachine;
    beforeEach(() => {
      newMachine = {
        name: faker.name.findName(),
        id: faker.internet.id().toLowerCase(),
        password: 'password1',
        role: 'machine',
      };
    });

    test('should correctly validate a valid machine', async () => {
      await expect(new Machine(newMachine).validate()).resolves.toBeUndefined();
    });

    test('should throw a validation error if id is invalid', async () => {
      newMachine.id = 'invalidId';
      await expect(new Machine(newMachine).validate()).rejects.toThrow();
    });

    test('should throw a validation error if password length is less than 8 characters', async () => {
      newMachine.password = 'passwo1';
      await expect(new Machine(newMachine).validate()).rejects.toThrow();
    });

    test('should throw a validation error if password does not contain numbers', async () => {
      newMachine.password = 'password';
      await expect(new Machine(newMachine).validate()).rejects.toThrow();
    });

    test('should throw a validation error if password does not contain letters', async () => {
      newMachine.password = '11111111';
      await expect(new Machine(newMachine).validate()).rejects.toThrow();
    });

    test('should throw a validation error if role is unknown', async () => {
      newMachine.role = 'invalid';
      await expect(new Machine(newMachine).validate()).rejects.toThrow();
    });
  });

  describe('Machine toJSON()', () => {
    test('should not return machine password when toJSON is called', () => {
      const newMachine = {
        name: faker.name.findName(),
        id: faker.internet.id().toLowerCase(),
        password: 'password1',
        role: 'machine',
      };
      expect(new Machine(newMachine).toJSON()).not.toHaveProperty('password');
    });
  });
});
