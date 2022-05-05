const httpStatus = require('http-status');
const pick = require('../utils/pick');
const ApiError = require('../utils/ApiError');
const catchAsync = require('../utils/catchAsync');
const { machineService } = require('../services');

const createMachine = catchAsync(async (req, res) => {
  const machine = await machineService.createMachine(req.body);
  res.status(httpStatus.CREATED).send(machine);
});

const getMachines = catchAsync(async (req, res) => {
  const result = await machineService.getAll();
  res.send(result);
});

const getMachine = catchAsync(async (req, res) => {
  const machine = await machineService.getMachineById(req.params.id);
  if (!machine) {
    throw new ApiError(httpStatus.NOT_FOUND, 'Machine not found');
  }
  res.send(machine);
});

const updateMachine = catchAsync(async (req, res) => {
  const machine = await machineService.updateMachineById(req.params.id, req.body);
  res.send(machine);
});

const deleteMachine = catchAsync(async (req, res) => {
  await machineService.deleteMachineById(req.params.id);
  res.status(httpStatus.NO_CONTENT).send();
});

module.exports = {
  createMachine,
  getMachines,
  getMachine,
  updateMachine,
  deleteMachine,
};
