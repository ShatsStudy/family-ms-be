require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const config = require('./config/config');
const apiRouter = require('./api/v1/routes/index.route');
const upload = require('./config/multer');
require('./config/mongoose');

const { port } = config;

const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(upload.single('avatar'));

app.use('/api/v1', apiRouter);

app.listen(port, () => {
  console.log(`Server running at port ${port}/`);
});
