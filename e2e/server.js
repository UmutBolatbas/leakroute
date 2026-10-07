// Temporary end-to-end test for the PR comment. Not meant to be merged.
const express = require('express');
const app = express();

app.delete('/api/admin/users/:id', (req, res) => res.json({ ok: true }));

module.exports = app;
