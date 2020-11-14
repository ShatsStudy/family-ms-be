const hbs = require('nodemailer-express-handlebars');
const nodemailer = require('nodemailer');
const path = require('path');
const {
  smtpEmail,
  smtpEmailPass,
} = require('./config');

const smtpTransport = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  requireTLS: true,
  auth: {
    user: smtpEmail,
    pass: smtpEmailPass,
  },
  tls: {
    rejectUnauthorized: false
  },
});

const handlebarsOptions = {
  viewEngine: {
    extName: '.html',
    partialsDir: path.resolve('../api/templates'),
  },
  viewPath: path.resolve('./api/templates'),
  extName: '.html',
};

smtpTransport.use('compile', hbs(handlebarsOptions));

module.exports = smtpTransport;
