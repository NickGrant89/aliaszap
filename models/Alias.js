const mongoose = require('mongoose');

const AliasSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  alias: { type: String, required: true, unique: true },
  forwardTo: { type: String, required: true },
  active: { type: Boolean, default: true },
  label: { type: String, default: '' },
  blockSpam: { type: Boolean, default: false },
  emailCount: { type: Number, default: 0 },
  spamCount: { type: Number, default: 0 },
  expiresAt: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now }
});

// Add indexes
AliasSchema.index({ userId: 1 });
AliasSchema.index({ alias: 1 });
AliasSchema.index({ expiresAt: 1 });

module.exports = mongoose.model('Alias', AliasSchema);