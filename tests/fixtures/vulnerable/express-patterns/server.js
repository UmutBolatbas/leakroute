const express = require('express');
const auth = require('./auth');

const app = express();

require('./routes/legacy')(app);
app.use(require('./routes/items'));
app.use('/api/secure', auth.required, require('./routes/secure'));

app.listen(3000);
