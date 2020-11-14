const express = require('express');
const upload = require('../../../config/multer');
const controller = require('../controllers/AuthController');

const router = express.Router();

router.post('/login', controller.signin);

router.post('/signup', upload.single('avatar'), controller.signup);

router.post('/forgot_password', controller.forgotPassword);

router.post('/recover_password', controller.recoverPassword);

router.post('/validate_recovery', controller.validateRecovery);

module.exports = router;
