const express = require('express');
const controller = require('../controllers/UserController');

const router = express.Router();

router.route('/')
  .get(controller.getAll)

  .delete(controller.deleteOne)

  .put(controller.updateOne);

router.get('/:id', controller.getOne);

router.put('/watched_issues', controller.updateWatched);

router.post('/change_avatar', controller.changeAvatar);

module.exports = router;
