// =================================================================
// 1. IMPORTS
// =================================================================
require('dotenv').config();
const mongoose = require('mongoose');
const express = require('express');
const cors = require ('cors');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
// const { default: Sendchamp } = require('sendchamp'); 
// const Sendchamp = require('sendchamp').default; 
// ...
//const Sendchamp = require('sendchamp').default; // Accesses the default export
// Temporarily comment out the failing import:


// =================================================================
// 2. CONFIGURATION & DATABASE CONNECTION
// =================================================================
const app = express();
app.set('trust proxy', 1); // Required for Render/proxy services for rate-limiting
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key'; // Debug: Use ENV variable
const MONGO_URI = process.env.MONGO_URI;

// 3a. CORS Configuration (Allows cross-origin requests)
app.use(cors({
    origin: '*', // Allow ALL origins temporarily
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true, 
}));

// =================================================================
// 3b. Body Parser (MUST be before routes)
// =================================================================
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // Good practice to include

// Initialize Sendchamp Client
let sendchampClient = null;
/*// The Sendchamp client is not initialized to bypass the CRITICAL ERROR.
// This allows the rest of the application (login, register) to function.
try {
    const publicKey = process.env.SENDCHAMP_PUBLIC_KEY;
    const baseUrl = process.env.SENDCHAMP_BASE_URL;

    if (!publicKey || !baseUrl) {
        throw new Error('Sendchamp keys (PUBLIC_KEY or BASE_URL) not configured in environment variables.');
    }

    sendchampClient = new Sendchamp({ 
        publicKey: publicKey,
        baseUrl: baseUrl 
    });
    console.log('Sendchamp Client Initialized. Ready for SMS service.');

} catch (error) {
    console.error('CRITICAL ERROR: Sendchamp Initialization Failed:', error.message);
    
    // Continue running the app without SMS functionality if needed, 
    // but log the error to alert the developer.
}
*/
// --- Database Connection ---
// MONGO_URI is defined above as const MONGO_URI = process.env.DB_CONNECTION_STRING;

// Use MONGO_URI and the fallback for stability, keeping your connection options.
mongoose.connect(MONGO_URI || 'mongodb://localhost/temp_db', {
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
})
    .then(() => {
        console.log("MongoDB Connection Successful! 🥳");
    })
    .catch((err) => {
        // Log the error and exit the process if connection fails.
        console.error("MongoDB Connection Error:", err);
        process.exit(1); 
    });

// =================================================================
// 2.5 MODELS
// =================================================================
const User = mongoose.model('user', new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    date: { type: Date, default: Date.now },

    // START: NEW FIELD FOR USER-CONFIGURED CONTACTS
    emergencyContacts: [{
        type: String,   // Store each phone number as a string
        trim: true,     // Remove any leading/trailing spaces
        default: []     // Default to an empty array if the user hasn't set any
    }],

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
//app.use(helmet());

// 3b. Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
});
//app.use(limiter); 

// 3c. CORS Configuration (Corrected for your domains)
//const allowedOrigins = [
    'https://amini-app-new.onrender.com', // Your backend URL
    'https://amini-frontend-client.vercel.app', // Example Vercel primary domain
    'https://amini-app.com', 
    'https://www.amini-app.com', 
    'https://amini-frontend-client-8jov8es3r.vercel.app', // Specific Vercel deployment URL
    'http://localhost:5500', // Local development
//];



// =================================================================
// 3e. STATIC FILES & FRONTEND
// =================================================================

// Tell Express to serve files (CSS, JS, Images) from the root folder
app.use(express.static(__dirname));

// Serve the index.html file when someone visits the main domain
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});


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

// =================================================================
// 5a. FRONTEND & PUBLIC ROUTES
// =================================================================

// 1. SERVE STATIC FILES (CSS, JS, Images)
// This ensures your styles load correctly from the root amini-app folder
app.use(express.static(__dirname));

// 2. SERVE THE MAIN UX
// This MUST be the first route so users see the website immediately
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 3. HEALTH CHECK (Optional, but good for Render logs)
app.get('/status', (req, res) => {
    res.json({ status: 'Live', database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected' });
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
        body('email', 'Email field requires a valid email address.').isEmail(),
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

// ==========================================
// EMERGENCY ALERT ROUTE
// ==========================================
app.post('/api/alerts', async (req, res) => {
    try {
        // 1. Get the data sent from the frontend
        const { latitude, longitude, timestamp } = req.body;
        
        // 2. (Optional) Get the user info from the Token
        // For now, we will just log it to the console to prove it works
        console.log(`🚨 SOS RECEIVED! 🚨`);
        console.log(`Location: ${latitude}, ${longitude}`);
        console.log(`Time: ${timestamp}`);

        // 3. Save to Database (Example logic)
        // const newAlert = await Alert.create({ latitude, longitude, user: req.user.id });

        // 4. Send success back to the phone/browser
        res.status(200).json({ message: "Alert received and broadcasted!" });

    } catch (err) {
        console.error("Server failed to process SOS:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});


// User report endpoint (SOS trigger)
app.post('/api/report', authMiddleware, async (req, res) => {
    try {
        const { message, location } = req.body;
        const userEmail = req.user.email;
        
        // --- START: Merged Logic from Your Existing Block ---
        // CRITICAL FIX: Ensure location is at least an empty object for safe reading
        const locationToUse = location || {}; 
        
        // This check is good if the frontend expects a 'message' field
        if (!message) {
             console.warn(`SOS Report from ${userEmail}: Missing message body.`);
        }
        
        // 1. Find the user and retrieve their contacts and ID (NEEDED for MongoDB and alerts)
        // NOTE: We need to find the user BEFORE saving the report to link the user ID.
        const user = await User.findOne({ email: userEmail });
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        
        // 2. Prepare the data for the report
        const locationUrl = (locationToUse.latitude && locationToUse.longitude)
            ? `https://maps.google.com/maps/search/?api=1&query=${locationToUse.latitude},${locationToUse.longitude}`
            : 'Location data unavailable.';

        const newReport = new Report({
            userEmail: userEmail,
            user: user._id, // Use user._id from the lookup
            message: message || "No message provided.",
            location: locationToUse,
            locationUrl: locationUrl,
            timestamp: new Date(),
        });
        await newReport.save();
        console.log(`Report from ${userEmail} saved to MongoDB.`);
        // --- END: Merged Logic ---


        // 3. Send SMS to all emergency contacts using Sendchamp
        if (sendchampClient && user.emergencyContacts && user.emergencyContacts.length > 0) {
            console.log('Attempting to send SOS alerts via Sendchamp...');

            const smsPromises = user.emergencyContacts.map(async (contact) => {
                // Ensure the number is in the correct format
                const formattedContact = contact.startsWith('+') ? contact.substring(1) : contact;
                
                const messageBody = `🚨 EMERGENCY! ${user.firstName || user.email} needs help! Location: ${locationUrl}`;

                try {
                    const response = await sendchampClient.sms.send({
                        sender_name: 'AminiApp',
                        to: [formattedContact],
                        message: messageBody,
                        route: 'non_dnd' 
                    });

                    console.log(`Sendchamp SMS sent to ${contact}. Response:`, response.status);
                    return { contact, status: 'Sent', response: response.status };

                } catch (sendError) {
                    console.error(`Sendchamp SMS FAILED for ${contact}:`, sendError.message);
                    return { contact, status: 'Failed', error: sendError.message };
                }
            });

            await Promise.allSettled(smsPromises); 
        } else if (user.emergencyContacts.length === 0) {
            console.log('SOS processed: User has no emergency contacts set up.');
        } else {
            console.warn('SMS functionality disabled (Sendchamp client not initialized).');
        }

        res.status(200).json({ message: 'SOS report saved and alerts processed.', locationUrl });

    } catch (error) {
        console.error('SOS Report Error:', error.message);
        res.status(500).json({ message: 'Failed to process SOS report.', error: error.message });
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
// Route to update or set the user's emergency contacts
app.put('/api/users/contacts', authMiddleware, async (req, res) => {
    try {
        // Expects an array of phone numbers named 'contacts' in the request body
        const { contacts } = req.body; 

        if (!Array.isArray(contacts)) {
            return res.status(400).json({ message: 'Contacts must be provided as an array.' });
        }

        // Find the user by ID and update the emergencyContacts field
        const user = await User.findByIdAndUpdate(
            req.user.id,
            // Use the $set operator to replace the entire emergencyContacts array
            { $set: { emergencyContacts: contacts } },
            { new: true, select: '-password' } // Return the updated document, excluding password
        );

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        res.json({ 
            message: 'Emergency contacts updated successfully!', 
            contacts: user.emergencyContacts 
        });

    } catch (err) {
        console.error("Error updating contacts:", err.message);
        res.status(500).json({ message: 'Server Error during contact update.' });
    }
});

// =================================================================
// 6. START THE SERVER
// =================================================================
app.listen(PORT, () => {
    console.log(`Amini app is running on http://0.0.0.0:${PORT}`);});