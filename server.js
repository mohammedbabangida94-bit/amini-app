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

// Add this near the top of your server.js file
const twilio = require('twilio'); 

const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
// Initialize the Twilio client using the secrets from Render
const twilioClient = new twilio(accountSid, authToken);

// =================================================================
// 2. CONFIGURATION & DATABASE CONNECTION
// =================================================================
const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 10000;
// NOTE: Use environment variables for JWT_SECRET in production!
const JWT_SECRET = 'your-super-secret-key'; 

// 2. Call mongoose.connect ONCE with options
mongoose.connect(process.env.MONGO_URI, {
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
}) 
    .then(() => {
        console.log("MongoDB Connection Successful! 🥳(Via Env Variable)");
    })
    .catch((err) => {
        console.error("MongoDB Connection Error:", err);
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

const User = mongoose.model('user', UserSchema);

// 2.6 REPORT MODEL (To store user activities)
const ReportSchema = new mongoose.Schema({
    userEmail: {
        type: String,
        required: true
    },
    message: {
        type: String,
        required: true
    },
    location: {
        lat: Number,
        long: Number
    },
    // Using 'date' for consistency with Report model, same as 'timestamp'
    date: {
        type: Date,
        default: Date.now
    }
});

const Report = mongoose.model('report', ReportSchema);

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

// === FIX: DEFINE allowedOrigins variable and apply CORS middleware ===
const allowedOrigins = [
    'https://amini-app-new.onrender.com', 
    'http://127.0.0.1:5500', 
    'http://localhost:5500', 
    'https://127.0.0.1:5500',
    'https://amini-frontend-client.vercel.app',
    'https://amini-app.com', 
    'https://www.amini-app.com', 
    'https://amini-frontend-client-8jov8es3r.vercel.app' // NOTE: I recommend adding this specific domain too
];

app.use(cors({
    origin: allowedOrigins,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true, 
    }));
// === END CORS FIX ===

// Middleware to parse JSON request bodies. MUST come before the routes.
app.use(express.json());

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// =================================================================
// 4. AUTHENTICATION MIDDLEWARE
// =================================================================
const authMiddleware = (req, res, next) => {
    // We are using 'Authorization: Bearer <token>' standard header from the frontend
    const authHeader = req.header('Authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        // Fallback for x-auth-token header if client uses it
        const token = req.header('x-auth-token');
        if (!token) {
            return res.status(401).json({ message: 'No token, authorization denied' });
        }
        
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded.user;
            next(); 
        } catch (err) {
            return res.status(401).json({ message: 'Token is not valid' });
        }
        return;
    }

    const token = authHeader.split(' ')[1]; // Extract the token part
    
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
            // const errors = validationResult(req); // <-- COMMENT OUT
            // if (!errors.isEmpty()) {             // <-- COMMENT OUT
            //     return res.status(400).json({ errors: errors.array() }); // <-- COMMENT OUT
            // }                                   // <-- COMMENT OUT
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
            // const errors = validationResult(req); // <-- COMMENT OUT
            // if (!errors.isEmpty()) {             // <-- COMMENT OUT
            //     return res.status(400).json({ errors: errors.array() }); // <-- COMMENT OUT
            // }                                   // <-- COMMENT OUT
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

// NEW ROUTE: GET ACTIVITY LOG REPORTS 
app.get('/api/reports', authMiddleware, async (req, res) => {
    try {
        const userEmail = req.user.email; // Extracted from the token
        
        // Find all reports associated with this user, sorting by date descending and limiting
        const reports = await Report.find({ userEmail })
                                    .sort({ date: -1 }) // Sort by newest first (using the 'date' field)
                                    .limit(10); // Limit to last 10 reports
        
        // Send the reports back to the frontend
        res.status(200).json(reports);

    } catch (err) {
        console.error("Error fetching activity log:", err.message);
        res.status(500).send('Server Error');
    }
});


// User report endpoint (SOS trigger)
app.post('/api/report', authMiddleware, async (req, res) => {
    try {
        const { message, location } = req.body;
        const userEmail = req.user.email;

        if (!message) {
            return res.status(400).json({ message: 'Message is required' });
        }

        // 1. Create and save report to MongoDB 
        const newReport = new Report({
            userEmail,
            message,
            location: location || {} 
        });

        const savedReport = await newReport.save(); 
        console.log(`Report from ${userEmail} saved to MongoDB.`);

        // --- TWILIO SMS INTEGRATION ---
        const recipientPhoneNumber = process.env.TWILIO_RECIPIENT_NUMBER || '+2348069358541'; // Use ENV or your hardcoded number
        
        const alertMessage = `AMINI SOS: ${userEmail} needs help. Message: "${message}". Location: Lat ${location.lat || 'N/A'}, Long ${location.long || 'N/A'}`;
        
        try {
            const twilioResponse = await twilioClient.messages.create({
                body: alertMessage,
                to: recipientPhoneNumber, 
                from: process.env.TWILIO_PHONE_NUMBER // Your sender number from Render/Twilio
            });
            console.log(`Twilio Message Sent. SID: ${twilioResponse.sid}`);
        } catch (smsError) {
            console.error("CRITICAL SMS SEND FAILURE (Twilio):", smsError);
            // DO NOT crash the API, but log the error.
        }
        // --- END TWILIO SMS INTEGRATION ---

        // Send successful response to frontend
        res.status(201).json({ message: 'SOS report saved and alert triggered!' });

    } catch (err) {
        console.error("Error processing report:", err.message);
        res.status(500).send('Server Error');
    }
});


// =================================================================
// 6. START THE SERVER
// =================================================================
app.listen(PORT, () => {
    console.log(`Amini app is running on http://0.0.0.0:${PORT}`);
});

