const express = require('express');
const { listUsers, updateUser, showUser } = require('../controllers/users');

const router = express.Router();

router.get('/', listUsers); // expect: endpoint/express-unprotected-route
router.route('/:id').put(updateUser).get(showUser); // expect: endpoint/express-unprotected-route expect: endpoint/express-unprotected-route

module.exports = router;
