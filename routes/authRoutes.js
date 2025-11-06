const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Resend } = require('resend');
const User = require('../models/User');

const router = express.Router();

// Initialize Resend API client
const resend = new Resend(process.env.RESEND_API_KEY);

// Send password reset email using Resend
async function sendPasswordResetEmail(user, token) {
  const resetUrl = `https://passwordresetuk.netlify.app/reset-password/${token}`;
  const emailFrom = process.env.EMAIL_FROM || 'Password Reset <no-reply@yourapp.com>';

  try {
    await resend.emails.send({
      from: emailFrom,
      to: user.email,
      subject: 'Password Reset Request',
      text: `
You requested a password reset.

Click the link below to reset your password (valid for 1 hour):
${resetUrl}

If you did not request this, please ignore this email.
      `,
    });
    console.log(`✅ Password reset email sent to ${user.email}`);
  } catch (error) {
    console.error('❌ Email send error:', error);
    throw new Error('Email sending failed');
  }
}

// ✅ Register Route
router.post('/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'A user with this email already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();

    res.status(201).json({ message: 'User registered successfully!' });
  } catch (err) {
    console.error('❌ Registration error:', err);
    res.status(500).json({ message: 'Server error during registration.' });
  }
});

// ✅ Forgot Password Route
router.post('/forgot-password', async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(200).json({
        message: 'If a user with that email exists, a reset link has been sent.',
      });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    user.passwordResetExpires = Date.now() + 3600000; // 1 hour

    await user.save();
    await sendPasswordResetEmail(user, resetToken);

    res.status(200).json({
      message: 'If a user with that email exists, a reset link has been sent.',
    });
  } catch (err) {
    console.error('❌ Forgot Password Error:', err);
    res.status(500).json({ message: 'Server error.' });
  }
});

// ✅ Reset Password Route
router.post('/reset-password/:token', async (req, res) => {
  try {
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: 'Token is invalid or has expired.' });
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    user.password = hashedPassword;
    user.passwordResetToken = null;
    user.passwordResetExpires = null;
    await user.save();

    res.status(200).json({ message: 'Password reset successful!' });
  } catch (err) {
    console.error('❌ Reset Password Error:', err);
    res.status(500).json({ message: 'Server error.' });
  }
});

module.exports = router;
