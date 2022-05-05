const Joi = require('joi');
const { password, objectId } = require('./custom.validation');

const createMachine = {
  body: Joi.object().keys({
    id: Joi.string().required(),
    program: Joi.string().required(),
    timer: Joi.string().required(),
  }),
};

const getMachines = {
  query: Joi.object().keys({
    id: Joi.string(),
  }),
};

const getMachine = {
  params: Joi.object().keys({
    id: Joi.string().custom(objectId),
  }),
};

const updateMachine = {
  params: Joi.object().keys({
    id: Joi.string().required(),
  }),
  body: Joi.object()
    .keys({
      program: Joi.string(),
    })
    .min(1),
};

const deleteMachine = {
  params: Joi.object().keys({
    id: Joi.string().required(),
  }),
};

module.exports = {
  createMachine,
  getMachines,
  getMachine,
  updateMachine,
  deleteMachine,
};
