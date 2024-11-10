// Load environment variables from .env file
require('dotenv').config();

// Import Dependencies
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const path = require('path');
const cookieParser = require('cookie-parser'); // For parsing cookies
const cors = require('cors'); // Enable CORS
const rateLimit = require('express-rate-limit'); // Rate limiting
const helmet = require('helmet'); // Security headers
const morgan = require('morgan'); // HTTP request logging
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const session = require('express-session');
const { body, validationResult } = require('express-validator');
const User = require('./models/User');

// Initialize Express App
const app = express();

// 1. Body Parsing Middleware
app.use(express.json()); // Parse JSON bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies

// 2. Other Middleware
app.use(cookieParser()); // Parse cookies
app.use(cors({
    origin: 'http://localhost:3000', // Adjust based on your frontend's URL
    methods: ['GET', 'POST'],
    credentials: true
}));

// 3. Session Middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-very-secure-secret', // Use a strong secret in .env
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 4 * 60 * 60 * 1000, // 4 hours
        secure: process.env.NODE_ENV === 'production', // Set to true in production
        httpOnly: true,
        sameSite: 'lax',
    }
}));

// 4. Security Middleware
app.use(helmet());

// 5. Logging Middleware
app.use(morgan('dev'));

// 6. Rate Limiting Middleware
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // Limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Serve Static Files
app.use(express.static(path.join(__dirname, 'public')));

// 3. Session Management Middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 4 * 60 * 60 * 1000, // 4 hours
        secure: process.env.NODE_ENV === 'production', // Set to true in production
        httpOnly: true,
        sameSite: 'lax',
    }
}));

// 4. Configure Nodemailer
const transporter = nodemailer.createTransport({
    service: 'Gmail', // Use your email service
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// 5. Authentication Middleware
function isAuthenticated(req, res, next) {
    if (req.session.user && req.session.user.isVerified) {
        return next();
    }
    res.status(401).json({ message: 'Unauthorized. Please log in.' });
}

// 6. Serve HTML Files via Routes

// Root Route - Redirect to signup.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'signup.html'));
});

// Serve Sign-Up Page
app.get('/signup.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'signup.html'));
});

// Serve Login Page
app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Serve Verification Page
app.get('/verify.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'verify.html'));
});

// Serve Verification Failed Page
app.get('/verification-failed.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'verification-failed.html'));
});

// Serve Dashboard Page - Protected Route
app.get('/dashboard.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'dashboard.html'));
});

// 7. Serve Static Assets from Root and Subdirectories
app.use('/css', express.static(path.join(__dirname, 'css')));
app.use('/js', express.static(path.join(__dirname, 'js')));
app.use('/images', express.static(path.join(__dirname, 'images')));

// 8. Rate Limiting for Sign-Up Route
const signupLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // limit each IP to 10 sign-up requests per windowMs
    message: 'Too many accounts created from this IP, please try again after 15 minutes'
});

// 9. Sign-Up Route with Validation
app.post('/signup', [
    body('email').isEmail().withMessage('Enter a valid email address'),
    body('username').isLength({ min: 3 }).withMessage('Username must be at least 3 characters long'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    body('confirmPassword').custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error('Passwords do not match');
        }
        return true;
    })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ message: errors.array()[0].msg });
    }

    const { email, username, password } = req.body;

    try {
        // Check if user exists
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ message: 'Email or Username already exists.' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create verification token
        const verificationToken = crypto.randomBytes(32).toString('hex');
        const verificationExpires = Date.now() + 4 * 60 * 60 * 1000; // 4 hours

        // Create new user
        const newUser = new User({
            email,
            username,
            password: hashedPassword,
            verificationToken,
            verificationExpires,
        });

        await newUser.save();

        // Send verification email
        const verificationLink = `http://localhost:${process.env.PORT}/verify-email?token=${verificationToken}&email=${email}`;
        await transporter.sendMail({
            from: `"Your App Name" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Verify Your Email',
            html: `<p>Thank you for signing up! Please verify your email by clicking the link below:</p>
                   <a href="${verificationLink}">Verify Email</a>`,
        });

        res.status(200).json({ message: 'Signup successful! Please check your email to verify.' });
    } catch (error) {
        console.error('Sign-Up Error:', error);
        res.status(500).json({ message: 'Error signing up. Please try again.' });
    }
});

// 10. Email Verification Route
app.get('/verify-email', async (req, res) => {
    const { token, email } = req.query;

    if (!token || !email) {
        return res.redirect('/verification-failed.html');
    }

    try {
        const user = await User.findOne({
            email,
            verificationToken: token,
            verificationExpires: { $gt: Date.now() },
        });

        if (!user) {
            return res.redirect('/verification-failed.html');
        }

        user.isVerified = true;
        user.verificationToken = undefined;
        user.verificationExpires = undefined;
        await user.save();

        // Update session
        req.session.user = {
            id: user._id,
            email: user.email,
            username: user.username,
            isVerified: user.isVerified,
        };

        console.log('Email verified successfully for:', user.email); // Optional server-side logging

        return res.redirect('/verify.html?status=success');
    } catch (error) {
        console.error('Email Verification Error:', error);
        return res.redirect('/verification-failed.html');
    }
});

// 11. Logout Route
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout Error:', err);
            return res.status(500).json({ message: 'Could not log out. Please try again.' });
        }
        res.clearCookie('connect.sid'); // Name may vary based on your session configuration
        res.status(200).json({ message: 'Logout successful.' });
    });
});

// 12. Login Route
app.post('/login', [
    body('email').isEmail().withMessage('Please enter a valid email.'),
    body('password').notEmpty().withMessage('Password cannot be empty.')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        // Return validation errors
        return res.status(400).json({ message: errors.array()[0].msg });
    }

    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).json({ message: 'Invalid email or password.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid email or password.' });
        }

        if (!user.isVerified) {
            return res.status(403).json({ message: 'Please verify your email before logging in.' });
        }

        // Update session
        req.session.user = {
            id: user._id,
            email: user.email,
            username: user.username,
            isVerified: user.isVerified,
        };

        console.log('User logged in:', user.email); // Optional logging

        return res.status(200).json({ message: 'Login successful.' });
    } catch (error) {
        console.error('Login Error:', error);
        return res.status(500).json({ message: 'Server error. Please try again later.' });
    }
});

// 13. Start Server and Connect to MongoDB
const PORT = process.env.PORT || 3000;
mongoose.connect(process.env.MONGO_URI)
    .then(() => {
        console.log('Connected to MongoDB');
        app.listen(PORT, () => {
            console.log(`Server running on http://localhost:${PORT}`);
        });
    })
    .catch(err => console.error('MongoDB connection error:', err));

// 8. MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('MongoDB connected');
}).catch(err => {
    console.error('MongoDB connection error:', err);
});

const express = require('express');
const path = require('path');

// Serve static files from the current directory
app.use(express.static(__dirname));

// Clean URL routes
app.get('/home', (req, res) => {
    res.sendFile(path.join(__dirname, 'Home.html'));
});

app.get('/pricing', (req, res) => {
    res.sendFile(path.join(__dirname, 'Pricing.html'));
});

// Optional: Redirect `.html` URLs to clean URLs
app.get('/Home.html', (req, res) => {
    res.redirect('/home');
});

app.get('/Pricing.html', (req, res) => {
    res.redirect('/pricing');
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});