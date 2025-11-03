// =================================================================
// 1. IMPORTS
// =================================================================
require ('dotenv').config();
const mongoose = require('mongoose');
const cors = require('cors');
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// =================================================================
// 2. CONFIGURATION & DATABASE CONNECTION
// =================================================================
const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 10000;
const JWT_SECRET = 'your-super-secret-key'; // In a real app, use environment variables

// === START OF HARDCODED FINAL FIX ===
const FINAL_URI = "mongodb://mohammedbabangida94_db_user:NewSimplePassword!@cluster0-shard-00-00.pjcdfzt.mongodb.net:27017,cluster0-shard-00-01.pjcdfzt.mongodb.net:27017,cluster0-shard-00-02.pjcdfzt.mongodb.net:27017/aminidb?replicaSet=Cluster0&ssl=true&authSource=admin";
mongoose.connect(FINAL_URI, {
serverSelectionTimeoutMS: 5000,
socketTimeoutMS: 45000,
mongoose.connect(FINAL_URI)
  .then(() => {
    console.log("MongoDB Hardcoded Connection Successful!"); 
  })
  .catch((err) => {
    console.error("MongoDB Hardcoded Connection Error:", err);
    process.exit(1);
  });
// =================================================================
// 2.5 USER MODEL (Blueprint for the database)
// =================================================================
const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: { // Stores the HASHED password
        type: String,
        required: true
    },
    date: {
        type: Date,
        default: Date.now
    }
});

const User = mongoose.model('user', UserSchema); // Export the Model

// =================================================================
// 3. GLOBAL MIDDLEWARE (Order is very important here!)
// =================================================================

// Apply security headers FIRST
app.use(helmet());

// Apply rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(limiter); 

// Allow Cross-Origin Requests from all origins
app.use(cors()); 

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
        next(); 
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
    res.send('Welcome to the Amini App API! Use your Netlify URL to view the app.');
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

            // Check if user already exists in MongoDB
            let userExists = await User.findOne({ email }); 
            if (userExists) {
                return res.status(400).json({ message: 'User already exists' });
            }

            const salt = await bcrypt.genSalt(8);
            const hashedPassword = await bcrypt.hash(password, salt);

            // Create and save the new user to MongoDB
            const newUser = new User({ email, password: hashedPassword }); 
            await newUser.save(); 

            console.log('Registered User saved to MongoDB');
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
            
            // Find user in MongoDB
            const user = await User.findOne({ email });
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

// User report endpoint
app.post('/api/report', authMiddleware, (req, res) => {
    try {
        const { message, location } = req.body;

        if (!message) {
            return res.status(400).json({ message: 'Message is required' });
        }

        const userEmail = req.user.email;

        console.log(`--- NEW REPORT ---`);
        console.log(`From: ${userEmail}`);
        console.log(`Message: "${message}"`);
        
        if (location) {
            console.log(`Location: ${location.lat}, ${location.long}`);
            // 💡 TO-DO: In a real app, save this report data to a MongoDB collection
        } else {
            console.log(`Location: Not provided`);
        }
        console.log(`------------------`);

        res.status(201).json({ message: 'Report received successfully!' });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});


// =================================================================
// 6. START THE SERVER
// =================================================================
app.listen(PORT, () => {
    console.log(`Amini app is running on http://0.0.0.0:${PORT}`);
});