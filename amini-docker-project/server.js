const express = require('express');
const express = require('express');

// Constants
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0'; 

const app = express();

app.get('/', (req, res) => {
  // This is the updated message
  res.send('<h1>Hello from your Amini App!</h1><p>It is now running on Render.</p>');
});

app.listen(PORT, HOST, () => {
  console.log(`Amini app is running on http://${HOST}:${PORT}`);
});