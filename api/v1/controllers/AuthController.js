/* eslint-disable consistent-return */
/* eslint-disable no-underscore-dangle */
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const smtpTransport = require('../../../config/smtpTransport');
const User = require('../../../models/user.model');
const helpers = require('../../../utils/helpers');
const {
  JWT_SECRET,
  smtpEmail,
  arrKeys,
  frontURI,
} = require('../../../config/config');

const signin = async (req, res) => {
  const {
    login,
    password,
  } = req.body;
  try {
    const user = await User.findOne({ login }).exec();

    if (!user) {
      res.status(404).json({
        err: 'User not found',
      });
      return 0;
    }

    if (user.checkPassword(password)) {
      res.json({
        token: jwt.sign({
          id: user._id,
          type: user.type,
        }, JWT_SECRET, {}),
      });
      return 0;
    }

    res.status(400).json({
      err: 'passwords don\'t match',
    });
  } catch (err) {
    res.status(500).json({
      err,
    });
  }
};

const signup = async (req, res) => {
  const parameters = helpers.reducePropsToObject(arrKeys, req.body);

  if (!parameters.login) {
    parameters.login = `${parameters.firstName.toLowerCase()[0]}${parameters.lastName.toLowerCase().substring(0, 5)}hrms`;
  }
  if (!parameters.password) {
    parameters.password = crypto.randomBytes(4).toString('hex');
  }

  if (parameters.type) {
    parameters.type = parameters.type.toLowerCase();
  }

  const newUser = User({
    ...parameters,
    contacts: {
      contact_name: req.body.contact_name,
      contact_value: req.body.contact_value,
    },
  });

  if (req.body.dates) {
    newUser.dates = [...req.body.dates];
  } else {
    newUser.dates = [];
  }

  if (req.file) {
    newUser.photoURL = req.file.url;
    newUser.photoID = req.file.public_id;
  }

  const mailData = {
    to: newUser.email,
    from: smtpEmail,
    template: 'create-user-email',
    subject: 'Registration in HRMS',
    context: {
      name: newUser.firstName,
      login: newUser.login,
      password: newUser.password,
    },
  };

  let savedUser;
  try {
    savedUser = await newUser.save();
    await smtpTransport.sendMail(mailData);
    res.status(201).json({
      newUser,
    });
  } catch (err) {
    if (savedUser) {
      User.findByIdAndDelete(savedUser._id);
    }
    res.status(500).json({
      err,
    });
  }
};

const forgotPassword = async (req, res) => {
  const {
    email,
  } = req.body;
  try {
    let user = await User.findOne({
      email,
    });
    if (!user) {
      res.status(404).json({
        err: 'User not found',
      });
      return 0;
    }
    const token = crypto.randomBytes(20).toString('hex');

    user = await User.findByIdAndUpdate(user._id, {
      reset_password_token: token,
      reset_password_expires: Date.now() + 86400000,
    }, {
      upsert: true,
      new: true,
    }).exec();
    const data = {
      to: user.email,
      from: smtpEmail,
      template: 'forgot-password-email',
      subject: 'Password help has arrived!',
      context: {
        url: `${frontURI}/reset-password?token=${token}`,
        name: user.firstName,
      },
    };
    await smtpTransport.sendMail(data);
    res.json({
      msg: 'Email sent',
    });
  } catch (err) {
    res.status(500).json({ err });
  }
};

const recoverPassword = async (req, res) => {
  const {
    token,
    newPass,
  } = req.body;
  try {
    const user = await User.findOne({
      reset_password_token: token,
      reset_password_expires: {
        $gt: Date.now(),
      },
    }).exec();

    if (!user) {
      res.status(404).json({
        err: 'Reset password link is invalid or expired',
      });
      return 0;
    }

    user.password = newPass;
    user.reset_password_token = undefined;
    user.reset_password_expires = undefined;

    await user.save();

    const data = {
      to: user.email,
      from: smtpEmail,
      template: 'reset-password-email',
      subject: 'Password Reset Confirmation',
      context: {
        name: user.firstName,
      },
    };

    await smtpTransport.sendMail(data);

    res.json({
      msg: 'Changed succesfully',
    });
  } catch (err) {
    res.status(500).json({ err });
  }
  return 0;
};

const validateRecovery = async (req, res) => {
  const {
    token,
  } = req.body;
  try {
    const user = await User.findOne({
      reset_password_token: token,
      reset_password_expires: {
        $gt: Date.now(),
      },
    }).exec();

    if (!user) {
      res.status(404).json({
        err: 'Reset password link is invalid or expired',
      });
      return 0;
    }

    res.json({
      validate: 'Success',
    });
  } catch (err) {
    res.status(500).json({ err });
  }
};

module.exports = {
  signin,
  signup,
  forgotPassword,
  recoverPassword,
  validateRecovery,
};
