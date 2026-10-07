const { expressjwt } = require('express-jwt');

module.exports = {
  required: expressjwt({ secret: process.env.JWT_SECRET, algorithms: ['HS256'] }),
  optional: expressjwt({ secret: process.env.JWT_SECRET, algorithms: ['HS256'], credentialsRequired: false }),
};
