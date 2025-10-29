
// =================================================================
// 1. IMPORTS
// =================================================================
const cors = require('cors');
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
app.set('trust proxy', 1);
const PORT = process.env.PORT || 10000;
const JWT_SECRET = 'your-super-secret-key'; // In a real app, use environment variables

// This is a placeholder for your database.
const users = [];

// =================================================================
// 3. GLOBAL MIDDLEWARE (Order is very important here!)
// =================================================================

// Apply security headers FIRST
app.use(helmet());
app.use(cors());

// Apply rate limiting to all requests
const limiter = rateLimit({ // Define the limiter FIRST
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter); // Use the limiter AFTER

// Middleware to parse JSON request bodies. MUST come before the routes.
app.use(express.json());

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

/// =================================================================
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
    next(); // <-- THIS IS THE CRITICAL LINE
  } catch (err) {
    res.status(401).json({ message: 'Token is not valid' });
  }
};

// =================================================================
// 5. ROUTES
// =================================================================

// --- Public Routes ---

// Homepage route
app.get('/', (req, res) => {
  res.send('Welcome to the Amini App API!');
});

// User registration endpoint
app.post('/register',
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password } = req.body;
      const userExists = users.find(user => user.email === email);
      if (userExists) {
        return res.status(400).json({ message: 'User already exists' });
      }

      const salt = await bcrypt.genSalt(8);
      const hashedPassword = await bcrypt.hash(password, salt);
      const newUser = { email, password: hashedPassword };
      users.push(newUser);

      console.log('Registered Users:', users);
      res.status(201).json({ message: 'User registered successfully!' });
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);

// User login endpoint
app.post('/login',
  body('email').isEmail(),
  body('password').exists(),
  async (req, res) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password } = req.body;
      const user = users.find(user => user.email === email);
      if (!user) {
        return res.status(400).json({ message: 'Invalid credentials' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: 'Invalid credentials' });
      }

      const payload = { user: { email: user.email } };
      jwt.sign(
        payload,
        JWT_SECRET,
        { expiresIn: 3600 },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
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