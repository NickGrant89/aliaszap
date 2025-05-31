const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const csurf = require('csurf');
const rateLimit = require('express-rate-limit');
const routes = require('./routes/index');
const User = require('./models/User');
require('dotenv').config();

const app = express();

// MongoDB
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Stripe Webhook (before csurf)
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
app.post('/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET || 'your_webhook_secret');
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.client_reference_id;
    await User.updateOne({ _id: userId }, { plan: 'basic' });
  }
  res.json({ received: true });
});

app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set to true in production
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(csurf());
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});
app.use('/create-alias', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10
}));
app.set('view engine', 'pug');
app.use(express.static('public'));

// Passport
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
  const user = await User.findOne({ email });
  if (!user) return done(null, false, { message: 'Incorrect email.' });
  if (!await bcrypt.compare(password, user.password)) return done(null, false, { message: 'Incorrect password.' });
  return done(null, user);
}));
passport.serializeUser((user, done) => done(null, user._id));
passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

// Routes
app.use('/', routes);

// Error handling
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    res.status(403).render('error', { error: 'Invalid CSRF token. Please try again.' });
  } else {
    console.error(err.stack);
    res.status(500).render('error', { error: 'Something went wrong!' });
  }
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));