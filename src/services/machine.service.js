const httpStatus = require('http-status');
const { Machine } = require('../models');
const ApiError = require('../utils/ApiError');

/**
 * Create a machine
 * @param {Object} machineBody
 * @returns {Promise<Machine>}
 */
const createMachine = async (machineBody) => {
  if (await Machine.isIdTaken(machineBody.id)) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Id already taken');
  }
  return Machine.create(machineBody);
};

/**
 * Get machine by id
 * @param {ObjectId} id
 * @returns {Promise<Machine>}
 */
const getMachineById = async (id) => {
  return Machine.findById(id);
};


/**
 * Update machine by id
 * @param {ObjectId} id
 * @param {Object} updateBody
 * @returns {Promise<Machine>}
 */
const updateMachineById = async (id, updateBody) => {
  const machine = await getMachineById(id);
  if (!machine) {
    throw new ApiError(httpStatus.NOT_FOUND, 'Machine not found');
  }
  if (updateBody.id && (await Machine.isIdTaken(updateBody.id, id))) {
    throw new ApiError(httpStatus.BAD_REQUEST, 'Id already taken');
  }
  Object.assign(machine, updateBody);
  await machine.save();
  return machine;
};

/**
 * Delete machine by id
 * @param {ObjectId} id
 * @returns {Promise<Machine>}
 */
const deleteMachineById = async (id) => {
  const machine = await getMachineById(id);
  if (!machine) {
    throw new ApiError(httpStatus.NOT_FOUND, 'Machine not found');
  }
  await machine.remove();
  return machine;
};

module.exports = {
  createMachine,
  queryMachines,
  getMachineById,
  getMachineById,
  updateMachineById,
  deleteMachineById,
};
