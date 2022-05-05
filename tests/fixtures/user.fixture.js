const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const faker = require('faker');
const Machine = require('../../src/models/machine.model');

const password = 'password1';
const salt = bcrypt.genSaltSync(8);
const hashedPassword = bcrypt.hashSync(password, salt);

const machineOne = {
  _id: mongoose.Types.ObjectId(),
  name: faker.name.findName(),
  id: faker.internet.id().toLowerCase(),
  password,
  role: 'machine',
  isIdVerified: false,
};

const machineTwo = {
  _id: mongoose.Types.ObjectId(),
  name: faker.name.findName(),
  id: faker.internet.id().toLowerCase(),
  password,
  role: 'machine',
  isIdVerified: false,
};

const admin = {
  _id: mongoose.Types.ObjectId(),
  name: faker.name.findName(),
  id: faker.internet.id().toLowerCase(),
  password,
  role: 'admin',
  isIdVerified: false,
};

const insertMachines = async (machines) => {
  await Machine.insertMany(machines.map((machine) => ({ ...machine, password: hashedPassword })));
};

module.exports = {
  machineOne,
  machineTwo,
  admin,
  insertMachines,
};
