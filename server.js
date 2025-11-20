// Server Dependencies and Setup
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const twilio = require('twilio');
const cookieParser = require('cookie-parser');
require('dotenv').config(); // Ensure your environment variables load

const app = express();

// --- Configuration ---
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'your_secret_key';

// Twilio Setup
const TWILIO_ACCOUNT_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER; 
const twilioClient = new twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);

// --- Middleware ---
app.use(express.json());
app.use(cookieParser());

// --- Database Connection ---
mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB connected successfully'))
    .catch(err => console.error('MongoDB connection error:', err));

// --- Mongoose Schemas (User & Report) ---
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    date: { type: Date, default: Date.now },
    
    // NEW FIELD for user-configured contacts
    emergencyContacts: [{
        type: String,
        trim: true,
        default: []
    }],
});

const ReportSchema = new mongoose.Schema({
    userEmail: { type: String, required: true },
    message: { type: String, required: true },
    date: { type: Date, default: Date.now },
    location: {
        lat: { type: Number },
        long: { type: Number }
    }
});

const User = mongoose.model('User', UserSchema);
const Report = mongoose.model('Report', ReportSchema);


// --- Authentication Middleware ---
const authMiddleware = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ message: 'Access denied. No token provided.' });
    }
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // Contains { id: userId, email: userEmail }
        next();
    } catch (ex) {
        res.status(400).json({ message: 'Invalid token.' });
    }
};
// Alias for ensureAuthenticated
const ensureAuthenticated = authMiddleware;


// =========================================================================
//                             APPLICATION ROUTES
// =========================================================================

// Root Route (for testing deployment)
app.get('/', (req, res) => {
    res.send('Amini App Backend Running');
});

// User Registration
app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'User already exists' });
        }
        
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        user = new User({ email, password: hashedPassword });
        await user.save();
        
        // Auto-login after registration
        const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        res.cookie('token', token, { httpOnly: true, maxAge: 604800000 }); // 7 days
        
        res.status(201).json({ message: 'User registered and logged in successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during registration' });
    }
});

// User Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        
        const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        res.cookie('token', token, { httpOnly: true, maxAge: 604800000 }); // 7 days
        
        res.status(200).json({ message: 'Logged in successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error during login' });
    }
});

// New Route: Save User Emergency Contacts 
app.post('/api/contacts', ensureAuthenticated, async (req, res) => {
    try {
        // NOTE: req.user.id is used if JWT payload uses 'id', req.user._id if payload uses '_id'
        const userId = req.user.id; 
        const { contacts } = req.body; // Expects an array of phone numbers from frontend

        // 1. Validation 
        if (!contacts || !Array.isArray(contacts) || contacts.length === 0) {
            return res.status(400).json({ success: false, message: 'Please provide at least one emergency contact.' });
        }
        if (contacts.length > 3) {
            return res.status(400).json({ success: false, message: 'You can set a maximum of 3 emergency contacts.' });
        }

        // 2. Update the user's document
        const updatedUser = await User.findByIdAndUpdate(userId, {
            emergencyContacts: contacts.map(c => c.trim()) // Store clean, trimmed numbers
        }, { new: true }); 

        if (!updatedUser) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        console.log(`User ${userId} successfully updated emergency contacts.`);
        res.json({ success: true, message: 'Emergency contacts saved successfully.' });

    } catch (error) {
        console.error('Error saving contacts:', error);
        res.status(500).json({ success: false, message: 'Server error saving contacts.' });
    }
});


// User Report Endpoint (SOS trigger) - Logic updated to prioritize user contacts
app.post('/api/report', authMiddleware, async (req, res) => {
    try {
        const { message, location } = req.body;
        const userEmail = req.user.email;
        const locationToUse = location || {}; 
        
        if (!message) {
            return res.status(400).json({ message: 'Message is required' });
        }
        
        // 1. Determine Recipients
        const userProfile = await User.findOne({ email: userEmail });
        let recipients = [];

        if (userProfile && userProfile.emergencyContacts && userProfile.emergencyContacts.length > 0) {
            // Priority 1: Use the user's personal contacts
            recipients = userProfile.emergencyContacts;
        } else if (process.env.TWILIO_RECIPIENT_NUMBERS) {
            // Priority 2 (Fallback): Use the hardcoded list (e.g., office numbers)
            recipients = process.env.TWILIO_RECIPIENT_NUMBERS.split(',').map(n => n.trim());
        }

        // 2. Create and save report to MongoDB 
        const newReport = new Report({ userEmail, message, location: locationToUse });
        await newReport.save(); 
        console.log(`Report from ${userEmail} saved to MongoDB.`);

        // 3. --- TWILIO SMS INTEGRATION (MULTI-RECIPIENT) ---
        if (recipients.length > 0 && TWILIO_PHONE_NUMBER) {
            // Construct a map link for easier access
            const mapLink = locationToUse.lat && locationToUse.long 
                            ? `https://maps.google.com/maps?q=${locationToUse.lat},${locationToUse.long}` 
                            : 'Location unavailable.';
            
            const alertMessage = `AMINI SOS: ${userEmail} needs help. Message: "${message}". Location: ${mapLink}`;
            
            const smsPromises = recipients.map(number => {
                return twilioClient.messages.create({
                    body: alertMessage,
                    to: number, 
                    from: TWILIO_PHONE_NUMBER
                });
            });

            try {
                await Promise.all(smsPromises);
                console.log(`Twilio: Alert sent to ${recipients.length} contact(s).`);
            } catch (smsError) {
                console.error("CRITICAL SMS SEND FAILURE (Twilio):", smsError);
            }
        } else {
            console.warn("TWILIO SKIPPED: No recipients or Twilio number configured.");
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
        const userEmail = req.user.email; 
        
        const reports = await Report.find({ userEmail })
                                   .sort({ date: -1 })
                                   .limit(10);
        
        res.status(200).json(reports);

    } catch (err) {
        console.error("Error fetching activity log:", err.message);
        res.status(500).json({ message: 'Server Error' });
    }
});


// --- Server Initialization ---
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});