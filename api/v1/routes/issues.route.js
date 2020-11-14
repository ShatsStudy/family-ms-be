const express = require('express');
const controller = require('../controllers/IssuesController');

const router = express.Router();

router.route('/')
  .get(controller.getOneByQuery)
  .post(controller.createOne)
  .put(controller.updateOne);

router.delete('/:id', controller.deleteOne);

router.get('/all', controller.getAll);

router.put('/resolve', controller.updateForResolve);

router.put('/comment', controller.updateForComment);

module.exports = router;
