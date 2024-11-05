const express = require('express');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use(cors());

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/newsletter', { useNewUrlParser: true, useUnifiedTopology: true });

const emailSchema = new mongoose.Schema({
    email: String
});

const Email = mongoose.model('Email', emailSchema);

// Nodemailer setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'your-email@gmail.com',
        pass: 'your-email-password'
    }
});

// API endpoint to handle form submission
app.post('/signup', async (req, res) => {
    const { email } = req.body;

    // Save email to database
    const newEmail = new Email({ email });
    await newEmail.save();

    // Send welcome email
    const mailOptions = {
        from: 'your-email@gmail.com',
        to: email,
        subject: 'Welcome to FusionAI Newsletter',
        text: 'Thank you for signing up for our newsletter!'
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            return res.status(500).send(error.toString());
        }
        res.status(200).send('Signed up successfully');
    });
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

// Footer Newsletter Signup
const newsletterSection = `
<div class="newsletter-section">
    <h4>Stay Updated</h4>
    <form id="newsletter-form">
        <input type="email" name="email" placeholder="Enter your email" required>
        <button type="submit">Sign Up</button>
    </form>
</div>
`;

document.body.insertAdjacentHTML('beforeend', newsletterSection);

document.getElementById('newsletter-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const email = event.target.email.value;

    const response = await fetch('/signup', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email })
    });

    if (response.ok) {
        alert('Signed up successfully');
    } else {
        alert('Error signing up');
    }
});