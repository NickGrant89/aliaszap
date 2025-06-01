const mongoose = require('mongoose');

const AliasSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  alias: { type: String, required: true, unique: true },
  forwardTo: { type: String, required: true },
  active: { type: Boolean, default: true },
  label: { type: String, default: '' },
  blockSpam: { type: Boolean, default: false },
  emailCount: { type: Number, default: 0 }, // New: Track emails received
  spamCount: { type: Number, default: 0 }, // New: Track spam emails
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Alias', AliasSchema);