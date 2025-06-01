const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const csurf = require('csurf');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const winston = require('winston');
const cron = require('node-cron');
const routes = require('./routes/index');
const User = require('./models/User');
const Alias = require('./models/Alias');
require('dotenv').config();

const app = express();

// Logger setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Request logging middleware
app.use((req, res, next) => {
  logger.info('Request Received', {
    method: req.method,
    url: req.url,
    userId: req.user ? req.user._id.toString() : 'Unauthenticated',
    ip: req.ip,
    timestamp: new Date().toISOString()
  });
  next();
});

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
    }
  }
}));
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
    logger.error('Webhook Error:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.client_reference_id;
    await User.updateOne({ _id: userId }, { plan: 'basic' });
    logger.info('User Plan Updated:', { userId, plan: 'basic' });
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
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Cron job for alias expiration
cron.schedule('* * * * *', async () => {
  const now = new Date();
  try {
    const expiredAliases = await Alias.find({ expiresAt: { $lte: now }, active: true }).lean();
    if (expiredAliases.length > 0) {
      const userIds = [...new Set(expiredAliases.map(alias => alias.userId.toString()))];
      await Alias.updateMany(
        { expiresAt: { $lte: now }, active: true },
        { $set: { active: false } }
      );
      for (const userId of userIds) {
        const activeCount = await Alias.countDocuments({ userId: userId, active: true });
        await User.updateOne({ _id: userId }, { $set: { aliasCount: activeCount } });
        logger.info('Updated aliasCount for user:', { userId, activeCount });
      }
      logger.info('Marked aliases as inactive:', { count: expiredAliases.length, aliases: expiredAliases.map(a => a.alias), timestamp: now });
    } else {
      logger.info('No aliases to expire at', { timestamp: now });
    }
  } catch (err) {
    logger.error('Cron Job Error:', err);
  }
});

// MongoDB
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => logger.info('Connected to MongoDB'))
  .catch(err => logger.error('MongoDB connection error:', err));

// Routes
app.use('/', routes);

// Error handling
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    logger.error('CSRF Token Error:', err);
    res.status(403).render('error', { error: 'Invalid CSRF token. Please try again.' });
  } else {
    logger.error('Server Error:', err.stack);
    res.status(500).render('error', { error: 'Something went wrong!' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => logger.info(`Server running on http://localhost:${PORT}`));