const Departments = require('../../../models/department.model');
const config = require('../../../config/config');

const arrKeys = config.arrKeysDepartments;

const getAll = async (req, res) => {
  try {
    const departments = await Departments.find()
      .populate('employees', arrKeys)
      .exec();
    res.status(200).json(departments);
  } catch (err) {
    res.status(500).json({
      err,
    });
  }
};

const createOne = async (req, res) => {
  try {
    const newDepartment = Departments({
      name: req.body.name,
      position: req.body.position,
    });
    await newDepartment.save();
    res.status(201).json({
      added: 'Successfully',
    });
  } catch (err) {
    res.status(500).json({
      err,
    });
  }
};

const deleteOne = async (req, res) => {
  try {
    const { id } = req.body;
    const departments = await Departments.findByIdAndDelete(id)
      .exec();
    if (!departments) {
      res.status(404).json({
        err: 'Department not found',
      });
    }
    res.status(204).json({
      deleted: 'Successfully',
    });
  } catch (err) {
    res.status(500).json({
      err,
    });
  }
};

const getOne = async (req, res) => {
  try {
    const { id } = req.params;
    const departments = await Departments.findById(id)
      .populate('employees', ['firstName', 'lastName'])
      .exec();
    if (!departments) {
      res.status(404).json({
        err: 'Department not found',
      });
    }
    res.status(200).json(departments);
  } catch (err) {
    res.status(500).json({
      err,
    });
  }
};

const addEmployee = async (req, res) => {
  try {
    const { id } = req.body;
    let { employees } = req.body;
    const department = await Departments.findById(id);
    if (!department) {
      res.status(404).json({
        err: 'Department not found',
      });
    } else if (!req.body.employees) {
      res.json({
        err: 'You should enter id of employee',
      });
    }
    employees = Array.isArray(employees) ? employees : Array(employees);
    const existingEmployee = department.employees.map(item => item.toString());
    employees = employees.filter(item => !existingEmployee.includes(item));
    if (!employees.length) {
      res.status(400).json({
        err: 'User(s) already added',
      });
      return;
    }
    department.employees = [...department.employees, ...employees];
    department.save();
    res.status(200).send('User(s) added to department');
  } catch (err) {
    res.status(500).json({
      err,
    });
  }
};

module.exports = {
  getAll,
  createOne,
  deleteOne,
  getOne,
  addEmployee,
};
