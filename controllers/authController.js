const User = require('../models/User');
const crypto = require('crypto');
const sendEmail = require('../utils/sendEmail');


// ==============================
// REGISTER USER
// ==============================
exports.registerUser = async (req, res) => {
  try {
    const { email, password } = req.body;

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

    // ❌ DO NOT HASH HERE (handled in model)
    const user = new User({ email, password });
    await user.save();

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


// ==============================
// FORGOT PASSWORD
// ==============================
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        message: 'Email is required.',
      });
    }

    const user = await User.findOne({ email });

    // Prevent email enumeration attack
    if (!user) {
      return res.status(200).json({
        message:
          'If an account with that email exists, a reset link has been sent.',
      });
    }

    // Generate raw reset token
    const resetToken = crypto.randomBytes(32).toString('hex');

    // Hash token before saving to DB
    user.passwordResetToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');

    user.passwordResetExpires = Date.now() + 15 * 60 * 1000; // 15 minutes

    await user.save();

    const resetUrl = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;

    const message = `
      <h3>Password Reset Request</h3>
      <p>Click the link below to reset your password:</p>
      <a href="${resetUrl}">${resetUrl}</a>
      <p>This link will expire in 15 minutes.</p>
    `;

    await sendEmail(user.email, 'Password Reset Request', message);

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


// ==============================
// RESET PASSWORD
// ==============================
exports.resetPassword = async (req, res) => {
  try {
    const { password } = req.body;

    if (!password || password.length < 6) {
      return res.status(400).json({
        message: 'Password must be at least 6 characters long.',
      });
    }

    // Hash token from URL
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

    // Set new password (will be hashed in model middleware)
    user.password = password;

    // Clear reset fields
    user.passwordResetToken = null;
    user.passwordResetExpires = null;

    await user.save();

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