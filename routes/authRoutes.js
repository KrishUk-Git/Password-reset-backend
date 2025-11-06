const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const User = require('../models/User');

const router = express.Router();

async function sendPasswordResetEmail(user, token) {
  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
  port: 465,
  secure: true,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
    connectionTimeout: 10000,
  });

  const resetUrl = `https://passwordresetuk.netlify.app/reset-password/${token}`;
  const mailOptions = {
    to: user.email,
    from: process.env.EMAIL_USER,
    subject: 'Password Reset Request',
    text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n` +
          `Please click on the following link, or paste this into your browser to complete the process within one hour:\n\n` +
          `${resetUrl}\n\n` +
          `If you did not request this, please ignore this email and your password will remain unchanged.\n`,
  };

  await transporter.sendMail(mailOptions);
}

router.post('/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'A user with this email already exists.' });
    }
    const user = new User({ email, password });
    await user.save();
    res.status(201).json({ message: 'User registered successfully!' });
  } catch (err) {
    res.status(500).json({ message: 'Server error during registration.' });
  }
});

router.post('/forgot-password', async (req, res) => {
  try {
    console.log(req.body.email)
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(200).json({ message: 'If a user with that email exists, a reset link has been sent.' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    user.passwordResetExpires = Date.now() + 3600000; // 1 hour

    await user.save();
    await sendPasswordResetEmail(user, resetToken);

    res.status(200).json({ message: 'If a user with that email exists, a reset link has been sent.' });
  } catch (err) {
  console.error("❌ Forgot Password Error:", err);
  res.status(500).json({ message: 'Server error.', error: err.message });
}
});

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

    user.password = req.body.password;
    user.passwordResetToken = null;
    user.passwordResetExpires = null;
    await user.save();

    res.status(200).json({ message: 'Password reset successful!' });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

module.exports = router;