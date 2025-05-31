const mongoose = require('mongoose');

const AliasSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  alias: { type: String, required: true, unique: true },
  forwardTo: { type: String, required: true },
  active: { type: Boolean, default: true },
  label: { type: String, default: '' }, // New: User-defined label
  blockSpam: { type: Boolean, default: false }, // New: Spam blocking toggle
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Alias', AliasSchema);