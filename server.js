// =================================================================
// 1. IMPORTS
// =================================================================
const dotenv = require('dotenv');
dotenv.config();
const mongoose = require('mongoose');
const express = require('express');
const cors = require ('cors');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const sendchamp = require('sendchamp');

let sendchampClient;

try {
    // Look for the tool in the three most common hiding spots
    const SendchampTool = sendchamp.Sendchamp || sendchamp.default || sendchamp;
    
    sendchampClient = new SendchampTool({
        publicKey: process.env.SENDCHAMP_PUBLIC_KEY,
        stage: 'live'
    });
    console.log("✅ Sendchamp initialized successfully!");
} catch (err) {
    console.error("❌ Sendchamp initialization failed:", err.message);
}
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

// Global Logger: Place this before all routes
app.use((req, res, next) => {
    const timestamp = new Date().toLocaleString();
    console.log(`--- NEW REQUEST [${timestamp}] ---`);
    console.log(`Method: ${req.method}`);
    console.log(`URL:    ${req.url}`);
    console.log(`Body:   `, req.body); // This helps check if 'location' is arriving
    console.log(`---------------------------------`);
    next(); // This tells the server to move to the actual route logic
});

app.use(express.urlencoded({ extended: true })); // Good practice to include


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
// 4. UX & STATIC FILES (THE FIX)
// =================================================================

// Tell Express where your frontend files are
app.use(express.static(__dirname));

// Serve index.html as the primary entry point
app.get('/', (req, res) => {
    const indexPath = path.join(__dirname, 'index.html');
    console.log("🔍 Attempting to serve UX from:", indexPath);
    
    res.sendFile(indexPath, (err) => {
        if (err) {
            console.error("❌ UX Error: Cannot find file at", indexPath);
            res.status(404).send(`<h1>Server is Live</h1><p>But index.html was not found in: ${indexPath}</p>`);
        }
    });
});

// ==========================================
// 1. USER MODEL (RE-ADD THIS)
// ==========================================
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    emergencyContacts: [String], 
    firstName: String
});

const User = mongoose.model('User', userSchema);

// =================================================================
// 2.5 MODELS
// =================================================================
const reportSchema = new mongoose.Schema({
    userEmail: { type: String, required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    message: { type: String, required: true },
    location: {
        latitude: Number,
        longitude: Number
    },
    locationUrl: String,
    date: { type: Date, default: Date.now }
});

const Report = mongoose.model('Report', reportSchema);

// 3b. Rate Limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
});


// =================================================================
// 3c. CORS Configuration (Specific for your domains)
// =================================================================
const allowedOrigins = [
    'https://amini-app-new.onrender.com',
    'https://amini-frontend-client.vercel.app',
    'https://amini-app.com', 
    'https://www.amini-app.com', 
    'https://amini-frontend-client-8jov8es3r.vercel.app',
    'http://localhost:5500'
];

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true, 
}));

// =================================================================
// 5. UX & API ROUTES (SINGLE SOURCE OF TRUTH)
// =================================================================

// Step A: Serve static files ONCE
app.use(express.static(__dirname));

// Step B: Define the ROOT route ONCE with diagnostic logging
app.get('/', (req, res) => {
    const indexPath = path.join(__dirname, 'index.html');
    console.log("🔍 Serving UX from:", indexPath);
    res.sendFile(indexPath, (err) => {
        if (err) {
            console.error("❌ UX Error:", err.message);
            res.status(404).send(`Server is UP, but cannot find index.html at ${indexPath}`);
        }
    });
});

// Step C: Health Check
app.get('/status', (req, res) => {
    res.json({ 
        status: 'Live', 
        database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected' 
    });
});

// Step D: Registration (Keep this as is)
app.post('/register', [
    body('email', 'Please include a valid email').isEmail(),
    body('password', 'Password must be 6 or more characters').isLength({ min: 6 }),
], async (req, res) => {
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
    console.log("🚨 SOS ALERT RECEIVED from user:", req.user.id);
    console.log("Location Data:", req.body.location);
    try {
        console.log("✅ Report saved to database");

        // ... your logic to send SMS ...
        console.log("📲 Attempting to send SMS via Sendchamp...");
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
            ? `https://www.google.com/maps?q=${locationToUse.latitude},${locationToUse.longitude}`
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
                        sender_name: 'Sendchamp',
                        to: [formattedContact],
                        message: messageBody,
                        route: 'non_dnd' 
                    });
console.log("SENDCHAMP RAW RESPONSE:", JSON.stringify(response));
                    console.log(`Sendchamp SMS sent to ${contact}. Response:`, response.status);
                    return { contact, status: 'Sent', response: response.status };

                } catch (sendError) {
                    console.error(`Sendchamp SMS FAILED for ${contact}:`, sendError.message);
                    return { contact, status: 'Failed', error: sendError.message };
                }

                    
            });

            await Promise.allSettled(smsPromises);
            await Promise.all(smsPromises); 
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
        const { contacts } = req.body; 

        if (!Array.isArray(contacts)) {
            return res.status(400).json({ message: 'Contacts must be provided as an array.' });
        }

        const user = await User.findByIdAndUpdate(
            req.user.id,
            { $set: { emergencyContacts: contacts } },
            { new: true, select: '-password' }
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

