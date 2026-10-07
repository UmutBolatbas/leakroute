module.exports = function (app) {
  app.post('/api/legacy', (req, res) => res.json(req.body)); // expect: endpoint/express-unprotected-route
};
