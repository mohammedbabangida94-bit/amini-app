// =================================================================
// 1. IMPORTS
// =================================================================
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// =================================================================
// 2. CONFIGURATION & APP INITIALIZATION
// =================================================================
const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = 'your-super-secret-key'; // In a real app, use environment variables

// This is a placeholder for your database.
const users = [];

// =================================================================
// 3. GLOBAL MIDDLEWARE (Order is very important here!)
// =================================================================

// Apply security headers FIRST
app.use(helmet());

// Apply rate limiting to all requests
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Middleware to parse JSON request bodies. MUST come before the routes.
app.use(express.json());

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));


// =================================================================
// 4. AUTHENTICATION MIDDLEWARE
// =================================================================
const authMiddleware = (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) {
    return res.status(401).json({ message: 'No token, authorization denied' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Token is not valid' });
  }
};

// =================================================================
// 5. ROUTES
// =================================================================

// --- Public Routes ---
// Note: The logic for register/login is still missing.
// This is where you would hash the password and save the user.
// =================================================================
// 5. ROUTES
// =================================================================

// --- Public Routes ---

// ADD THIS ROUTE FOR THE HOMEPAGE
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Note: The logic for register/login is still missing.
// This is where you would hash the password and save the user.
app.post('/register',
  //... your existing register code
app.post('/register',
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  (req, res) => {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    // TODO: Add logic to hash password and save user to the 'users' array or a database
    res.status(201).json({ message: 'User registration endpoint hit. (Logic not implemented)' });
  }
);

app.post('/login',
  body('email').isEmail(),
  body('password').exists(),
  (req, res) => {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    // TODO: Add logic to find user, compare password, and generate JWT
    res.status(200).json({ message: 'User login endpoint hit. (Logic not implemented)' });
  }
);

// --- Protected Routes ---
app.get('/profile', authMiddleware, (req, res) => {
  res.json({ message: `Welcome to your profile, ${req.user.email}` });
});

app.get('/dashboard-data', authMiddleware, (req, res) => {
  res.json({ data: 'This is sensitive dashboard data.' });
});


// =================================================================
// 6. START THE SERVER (This is the very last thing)
// =================================================================
app.listen(PORT, () => {
  console.log(`Amini app is running on http://0.0.0.0:${PORT}`);
});