const router = require('express').Router();

router.put('/api/items/:id', (req, res) => res.json(req.body)); // expect: endpoint/express-unprotected-route

module.exports = router;
