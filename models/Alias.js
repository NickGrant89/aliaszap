const mongoose = require('mongoose');

const AliasSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  alias: { type: String, required: true },
  forwardTo: { type: String, required: true },
  active: { type: Boolean, default: true },
  label: String,
  expiresAt: Date,
  emailCount: { type: Number, default: 0 },
  spamCount: { type: Number, default: 0 },
  blockSpam: { type: Boolean, default: false },
  domain: { type: String, default: process.env.DOMAIN },
  spamBlocklist: { type: [String], default: [] }, // Custom blocklist for senders/domains
  enableAdvancedSpamDetection: { type: Boolean, default: false } // Toggle for keyword-based detection

  
});

// Add indexes
AliasSchema.index({ userId: 1 });
AliasSchema.index({ alias: 1 });
AliasSchema.index({ expiresAt: 1 });

module.exports = mongoose.model('Alias', AliasSchema);