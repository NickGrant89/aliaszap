const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  plan: { type: String, enum: ['free', 'basic'], default: 'free' },
  aliasCount: { type: Number, default: 0 },
  isAdmin: { type: Boolean, default: false } // Add admin role field
});

userSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 10);
  }
  next();
});

module.exports = mongoose.model('User', userSchema);