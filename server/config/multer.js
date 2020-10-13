const multer = require('multer');
const cloudinaryStorage = require('multer-storage-cloudinary');
const cloudinary = require('./cloudinary');

const storage = cloudinaryStorage({
  cloudinary,
  folder: 'hrms/avatars',
  allowedFormats: ['jpg', 'png'],
  transformation: [{ width: 500, height: 500, crop: 'limit' }],
});

const parser = multer({ storage });

module.exports = parser;
