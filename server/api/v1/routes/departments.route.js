const express = require('express');
const controller = require('../controllers/DepartmentsController');

const router = express.Router();

router.route('/')
  .get(controller.getAll)
  .post(controller.createOne)
  .delete(controller.deleteOne);

router.get('/:id', controller.getOne);
router.post('/users', controller.addEmployee);
module.exports = router;
