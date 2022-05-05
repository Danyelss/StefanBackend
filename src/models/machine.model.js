const mongoose = require('mongoose');
const { toJSON, paginate } = require('./plugins');

const machineSchema = mongoose.Schema(
  {
    id: {
      type: String,
      required: true,
      trim: true,
    },
    timer: {
      type: String,
      required: true,
      trim: true,
    },
    program: {
      type: String,
      required: true,
      trim: true,
    },
  },
  {
    timestamps: true,
  }
);

// add plugin that converts mongoose to json
machineSchema.plugin(toJSON);
machineSchema.plugin(paginate);

/**
 * @typedef Machine
 */
const Machine = mongoose.model('Machine', machineSchema);

module.exports = Machine;
