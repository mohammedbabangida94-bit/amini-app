
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
// 5. ROUTES (UPDATED SECTION)
// =================================================================

// --- Public Routes ---

// @route   POST /register
// @desc    Register a new 

// --- Public Routes ---

// Homepage route
app.get('/', (req, res) => {
  res.send('Welcome to the Amini App API!');
});


// User registration endpoint
app.post('/register',
  body('email').isEmail(),
  body('password').isLength({ min: 6 }),
  async (req, res) => { // Make sure it's async
    try {
      // Check for validation errors
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password } = req.body;

      // Check if user already exists
      const userExists = users.find(user => user.email === email);
      if (userExists) {
        return res.status(400).json({ message: 'User already exists' });
      }

      // Hash the password
      const salt = await bcrypt.genSalt(8); // Using 8 for speed on Render
      const hashedPassword = await bcrypt.hash(password, salt);

      // Save the new user
      const newUser = { email, password: hashedPassword };
      users.push(newUser);

      console.log('Registered Users:', users); // For debugging
      res.status(201).json({ message: 'User registered successfully!' });

    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server error');
    }
  }
);
// User login endpoint
  body('email').isEmail(),
  body('password').exists(),
  async (req, res) => { // Make sure it's an async function
    try {
      // Check for validation errors
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
      }

      const { email, password } = req.body;

      // Find the user
      const user = users.find(user => user.email === email);
      if (!user) {
        // We send "Invalid credentials" even if the user doesn't exist.
        // This prevents attackers from guessing which emails are registered.
        return res.status(400).json({ message: 'Invalid credentials' });
      }

      // --- THIS IS THE CRITICAL PART ---
      // Compare the plain-text password from the request with the
      // hashed password from the user in our 'database'
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: 'Invalid credentials' });
      }
      // --- END CRITICAL PART ---

      // Create JWT Payload
      const payload = {
        user: {
          email: user.email
        }
      };

      // Sign the token
      jwt.sign(
        payload,
        JWT_SECRET,
        { expiresIn: 3600 }, // Token expires in 1 hour
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

// @route   POST /login
// @desc    Authenticate user & get token
app.post(
  '/login',
  body('email').isEmail().withMessage('Please include a valid email'),
  body('password').exists().withMessage('Password is required'),
  async (req, res) => {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
      // 1. Find the user
      let user = users.find(u => u.email === email);
      if (!user) {
        return res.status(400).json({ message: 'Invalid Credentials' });
      }

      // 2. Compare the provided password with the stored hashed password
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: 'Invalid Credentials' });
      }

      // 3. If credentials are correct, create the JWT payload
      const payload = {
        user: {
          email: user.email,
          // You can add other user info here, but not the password!
        },
      };

      // 4. Sign the token and send it back to the client
      jwt.sign(
        payload,
        JWT_SECRET,
        { expiresIn: '1h' }, // Token expires in 1 hour
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );

    } catch (err) {
      console.error(err.message);
      res.status(500).send('Server Error');
    }
  }
);

// --- Protected Routes (No changes needed here) ---
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