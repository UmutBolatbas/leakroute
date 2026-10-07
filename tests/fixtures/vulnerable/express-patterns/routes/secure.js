const router = require('express').Router();

router.post('/notes', (req, res) => res.json(req.body));

module.exports = router;
