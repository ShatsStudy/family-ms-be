const mongoose = require('mongoose');

const { Schema } = mongoose;

const departmentSchema = new Schema(
  {
    name: {
      type: String,
      required: true,
    },
    employees: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    }],
    position: [{
      type: String,
      required: true,
    }],
  },
);

departmentSchema.set('toJSON', {
  transform(doc, ret) {
    const object = ret;
    delete object.__v;
    return object;
  },
});

const Department = mongoose.model('Department', departmentSchema);

module.exports = Department;
