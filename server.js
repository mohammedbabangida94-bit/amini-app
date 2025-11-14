// =================================================================
// 1. IMPORTS
// =================================================================
require('dotenv').config();
const mongoose = require('mongoose');
const cors = require('cors');
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
 const twilio = require('twilio'); 
// =================================================================
// 2. CONFIGURATION & DATABASE CONNECTION
// =================================================================
const app = express();
app.set('trust proxy', 1); // Required for Render/proxy services for rate-limiting
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key'; // Debug: Use ENV variable
const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER; 

// Initialize Twilio client
const twilioClient = new twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// Connect to Database
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
// 2.5 MODELS
// =================================================================
const User = mongoose.model('user', new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    date: { type: Date, default: Date.now }
}));

const Report = mongoose.model('report', new mongoose.Schema({
    userEmail: { type: String, required: true },
    message: { type: String, required: true },
    location: { lat: Number, long: Number },
    date: { type: Date, default: Date.now }
}));
    
// =================================================================
// 3. GLOBAL MIDDLEWARE (Order is critical!)
// =================================================================

// 3a. Security Headers (FIRST)
app.use(helmet());

// 3b. Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(limiter); 

// 3c. CORS Configuration (Corrected for your domains)
const allowedOrigins = [
    'https://amini-app-new.onrender.com', // Your backend URL
    'https://amini-frontend-client.vercel.app', // Example Vercel primary domain
    'https://amini-app.com', 
    'https://www.amini-app.com', 
    'https://amini-frontend-client-8jov8es3r.vercel.app', // Specific Vercel deployment URL
    'http://localhost:5500', // Local development
];

// 1. STANDARD CORS MIDDLEWARE
app.use(cors({
    origin: allowedOrigins,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true, 
})); 


// =================================================================
// 3d. Body Parser (MUST be before routes)
// =================================================================
app.use(express.json());
// ... rest of your middleware

// 3e. Static Files
app.use(express.static(path.join(__dirname, 'public')));


// =================================================================
// 4. AUTHENTICATION MIDDLEWARE (Cleaned and debugged)
// =================================================================

    const authMiddleware = (req, res, next) => {
    const token = req.header('x-auth-token'); 

if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }
    
try {
        // Debug: Correctly using JWT_SECRET variable
    const decoded = jwt.verify(token, JWT_SECRET); 
    req.user = decoded.user;
    next(); 

    } catch (err) {
     return res.status(401).json({ message: 'Token is not valid' });
    }
};

// =================================================================
// 5. ROUTES
// =================================================================

// --- 5a. Public Routes ---

 app.get('/', (req, res) => {
    res.send('Welcome to the Amini App API! Backend is live.');
});

// User registration endpoint
app.post(
    '/register', 
    [
        body('email', 'Please include a valid email').isEmail(),
        body('password', 'Password must be 6 or more characters').isLength({ min: 6 }),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

    try {
        const { email, password } = req.body;

        let userExists = await User.findOne({ email }); 
            if (userExists) {
                return res.status(400).json({ message: 'User already exists' });
            }

        const salt = await bcrypt.genSalt(8);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({ email, password: hashedPassword }); 
            await newUser.save(); 
            
            // Generate JWT after successful registration
            const payload = { user: { id: newUser.id, email: newUser.email } };

            jwt.sign(
                payload,
                JWT_SECRET,
                { expiresIn: 360000 },
                (err, token) => {
                    if (err) throw err;
                    res.status(201).json({ token, message: 'User registered successfully!' });
                }
            );

        } catch (err) {
            console.error(err.message);
            // Debug: Ensure JSON error response
            res.status(500).json({ message: 'Server Error during registration.' }); 
        }
    }
);

// User login endpoint (Complete Logic)
app.post(
    '/login', 
    [
        body('email', 'Please include a valid email').isEmail(),
        body('password', 'Password is required').exists(),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        
        try {
            const { email, password } = req.body;
            let user = await User.findOne({ email });

            if (!user) {
                return res.status(400).json({ message: 'Invalid Credentials' });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(400).json({ message: 'Invalid Credentials' });
            }

            // Generate JWT upon successful login
            const payload = { user: { id: user.id, email: user.email } };

            jwt.sign(
                payload,
                JWT_SECRET,
                { expiresIn: 360000 },
                (err, token) => {
                    if (err) {
                        // Debug: Handle JWT error gracefully
                        return res.status(500).json({ message: 'Token creation failed.' }); 
                    }
                    res.json({ token });
                }
            );
        } catch (err) {
            console.error(err.message);
            res.status(500).json({ message: 'Server Error during login.' });
        }
    }
);


// --- 5b. Protected Routes ---

// Route to fetch user profile data (Debug: Added missing route)
app.get('/profile', authMiddleware, async (req, res) => {
try {
        const user = await User.findById(req.user.id).select('-password'); 
        
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        
        res.json({ message: `Profile loaded successfully.`, user: { id: user.id, email: user.email } }); 
    }  catch (err) {
        console.error("Error fetching profile:", err.message);
res.status(500).json({ message: 'Server Error during profile fetch.' }); 
    }
});


// User report endpoint (SOS trigger)
app.post('/api/report', authMiddleware, async (req, res) => {
    try {
        const { message, location } = req.body;
        const userEmail = req.user.email;
        const recipientPhoneNumber = process.env.TWILIO_RECIPIENT_NUMBER; 

        if (!message) {
            return res.status(400).json({ message: 'Message is required' });
        }

        // 1. Create and save report to MongoDB 
        const newReport = new Report({ userEmail, message, location: location || {} });
        await newReport.save(); 
        console.log(`Report from ${userEmail} saved to MongoDB.`);

        // --- TWILIO SMS INTEGRATION ---
        if (recipientPhoneNumber && TWILIO_PHONE_NUMBER) {
            const alertMessage = `AMINI SOS: ${userEmail} needs help. Message: "${message}". Location: Lat ${location.lat || 'N/A'}, Long ${location.long || 'N/A'}`;
            
            try {
                await twilioClient.messages.create({
                    body: alertMessage,
                    to: recipientPhoneNumber, 
                    from: TWILIO_PHONE_NUMBER 
                });
                console.log(`Twilio Message Sent.`);
            } catch (smsError) {
                console.error("CRITICAL SMS SEND FAILURE (Twilio):", smsError);
            }
        } else {
            console.warn("TWILIO SKIPPED: Missing TWILIO_PHONE_NUMBER or TWILIO_RECIPIENT_NUMBER environment variable.");
        }
        // --- END TWILIO SMS INTEGRATION ---

     res.status(201).json({ message: 'SOS report saved and alert triggered!' });

    } catch (err) {
        console.error("Error processing report:", err.message);
        res.status(500).json({ message: 'Server Error' });
    }
});

// GET ACTIVITY LOG REPORTS 
app.get('/api/reports', authMiddleware, async (req, res) => {
    try {
        const userEmail = req.user.email; // Extracted from the token
        
        const reports = await Report.find({ userEmail })
                                     .sort({ date: -1 })
                                     .limit(10);
        
        res.status(200).json(reports);

    } catch (err) {
        console.error("Error fetching activity log:", err.message);
        res.status(500).json({ message: 'Server Error' });
    }
});


// =================================================================
// 6. START THE SERVER
// =================================================================
app.listen(PORT, () => {
    console.log(`Amini app is running on http://0.0.0.0:${PORT}`);});