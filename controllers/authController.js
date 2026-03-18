const User = require('../models/User');
const crypto = require('crypto');
const sendEmail = require('../utils/sendEmail');


exports.registerUser = async (req, res) => {
  try {
    let { email, password } = req.body;

    email = email.trim().toLowerCase();

    if (!email || !password) {
      return res.status(400).json({
        message: 'Email and password are required.',
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        message: 'Password must be at least 6 characters long.',
      });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({
        message: 'A user with this email already exists.',
      });
    }

    const user = new User({ email, password });
    await user.save();

    console.log("✅ User registered:", email);

    res.status(201).json({
      message: 'User registered successfully!',
    });
  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({
      message: 'Server error during registration.',
    });
  }
};


exports.forgotPassword = async (req, res) => {
  try {
    let { email } = req.body;

    email = email.trim().toLowerCase();

    console.log("📩 Email received:", email);

    const user = await User.findOne({ email });

    console.log("🔍 User found:", user);

    if (!user) {
      return res.status(200).json({
        message:
          'If an account with that email exists, a reset link has been sent.',
      });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');

    user.passwordResetToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');

    user.passwordResetExpires = Date.now() + 15 * 60 * 1000;

    await user.save();

    const resetUrl = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;

    const message = `
      <h3>Password Reset Request</h3>
      <p>Click the link below to reset your password:</p>
      <a href="${resetUrl}">${resetUrl}</a>
      <p>This link will expire in 15 minutes.</p>
    `;

    console.log("📨 Sending email to:", user.email);

    await sendEmail(user.email, 'Password Reset Request', message);

    console.log("✅ Reset email sent");

    res.status(200).json({
      message:
        'If an account with that email exists, a reset link has been sent.',
    });

  } catch (error) {
    console.error('❌ Forgot password error:', error);
    res.status(500).json({
      message: 'Server error.',
    });
  }
};


exports.resetPassword = async (req, res) => {
  try {
    const { password } = req.body;

    if (!password || password.length < 6) {
      return res.status(400).json({
        message: 'Password must be at least 6 characters long.',
      });
    }

    const hashedToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        message: 'Token is invalid or has expired.',
      });
    }

    user.password = password;
    user.passwordResetToken = null;
    user.passwordResetExpires = null;

    await user.save();

    console.log("🔑 Password reset successful for:", user.email);

    res.status(200).json({
      message: 'Password reset successful!',
    });

  } catch (error) {
    console.error('❌ Reset password error:', error);
    res.status(500).json({
      message: 'Server error.',
    });
  }
};