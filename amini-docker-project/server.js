const express = require('express');
const path = require('path'); // Import the 'path' module, which helps work with file paths

// Constants
const PORT = process.env.PORT || 3000; // IMPORTANT: Use Render's port, or 3000 for local
const HOST = '0.0.0.0'; // This is important for Docker

const app = express();

// This is the magic line!
// It tells Express to serve any file from the 'public' directory.
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, HOST, () => {
  console.log(`Amini app is running on http://${HOST}:${PORT}`);
});