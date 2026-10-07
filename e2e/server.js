// Temporary end-to-end test for the PR comment. Not meant to be merged.
const express = require('express');
const app = express();

app.delete('/api/admin/users/:id', (req, res) => res.json({ ok: true }));
app.post('/@UmutBolatbas <img src=https://example.com/x.png> https://example.com `x` [click](https://example.com)', (req, res) => res.end());

module.exports = app;
