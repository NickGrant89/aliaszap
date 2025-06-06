const mongoose = require('mongoose');

  const messageSchema = new mongoose.Schema({
    sender: { type: String, enum: ['user', 'admin'], required: true },
    message: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
  });

  const supportTicketSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    subject: { type: String, required: true },
    messages: [messageSchema], // Array of messages for conversation thread
    priority: { type: Boolean, default: false }, // True for paid plan users
    status: { type: String, enum: ['open', 'closed'], default: 'open' },
    createdAt: { type: Date, default: Date.now }
  });

  module.exports = mongoose.model('SupportTicket', supportTicketSchema);