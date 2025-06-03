const mongoose = require('mongoose');

  const supportTicketSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    subject: { type: String, required: true },
    message: { type: String, required: true },
    priority: { type: Boolean, default: false }, // True for paid plan users
    status: { type: String, enum: ['open', 'closed'], default: 'open' },
    createdAt: { type: Date, default: Date.now }
  });

  module.exports = mongoose.model('SupportTicket', supportTicketSchema);