const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const User = require('../models/User');

// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: 587,
  secure: false, // true for 465, false for other ports
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// POST /api/auth/forgot-password
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      // To prevent user enumeration, send a generic success response
      return res.status(200).json({ message: 'If your email is registered, you will receive a password reset link.' });
    }

    // Generate a random token
    const token = crypto.randomBytes(20).toString('hex');
    
    // Set token and expiry on user model
    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

    await user.save();

    // Create reset link
    const resetLink = `${process.env.CLIENT_URL}/reset-password/${token}`;

    // Email options
    const mailOptions = {
      to: user.email,
      from: `Password Reset <${process.env.EMAIL_USER}>`,
      subject: 'Password Reset Request',
      text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n` +
            `Please click on the following link, or paste this into your browser to complete the process:\n\n` +
            `${resetLink}\n\n` +
            `If you did not request this, please ignore this email and your password will remain unchanged.\n`,
    };

    // Send email
    await transporter.sendMail(mailOptions);
    
    res.status(200).json({ message: 'A password reset link has been sent to your email.' });

  } catch (error) {
    console.error('Forgot Password Error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


// GET /api/auth/reset-password/:token (Validate token)
router.get('/reset-password/:token', async (req, res) => {
    try {
        const user = await User.findOne({
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({ message: 'Password reset token is invalid or has expired.' });
        }

        res.status(200).json({ message: 'Token is valid.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});


// POST /api/auth/reset-password/:token (Reset the password)
router.post('/reset-password/:token', async (req, res) => {
    try {
        const user = await User.findOne({
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({ message: 'Password reset token is invalid or has expired.' });
        }

        // Set the new password
        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        await user.save();

        res.status(200).json({ message: 'Password has been updated successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;