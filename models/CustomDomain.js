const mongoose = require('mongoose');

const customDomainSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  domain: { type: String, required: true },
  verified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('CustomDomain', customDomainSchema);