const express = require('express');
const passport = require('passport');
const router = express.Router();
const User = require('../models/User');
const Alias = require('../models/Alias');
const AWS = require('aws-sdk');

AWS.config.update({ region: 'us-east-1' });
const ses = new AWS.SES();

// Middleware
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
};

// Home
router.get('/', (req, res) => {
  res.render('index', { user: req.user });
});

// Login
router.get('/login', (req, res) => {
  res.render('login', { error: req.session.messages || null, csrfToken: req.csrfToken() });
});
router.post('/login', passport.authenticate('local', {
  successRedirect: '/dashboard',
  failureRedirect: '/login',
  failureMessage: true
}));

// Signup
router.get('/signup', (req, res) => {
  res.render('signup', { error: null, csrfToken: req.csrfToken() });
});
router.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.render('signup', { error: 'Email already exists.', csrfToken: req.csrfToken() });
    const user = new User({ email, password });
    await user.save();
    req.login(user, () => res.redirect('/dashboard'));
  } catch (err) {
    res.render('signup', { error: 'Server error.', csrfToken: req.csrfToken() });
  }
});

// Dashboard
router.get('/dashboard', isAuthenticated, async (req, res) => {
  const aliases = await Alias.find({ userId: req.user._id });
  res.render('dashboard', { user: req.user, aliases, csrfToken: req.csrfToken() });
});

// Create Alias
router.post('/create-alias', isAuthenticated, async (req, res) => {
  const { user } = req;
  const { label } = req.body;
  if (user.plan === 'free' && user.aliasCount >= 5) {
    return res.render('dashboard', {
      user,
      aliases: await Alias.find({ userId: user._id }),
      error: 'Upgrade to create more aliases.',
      csrfToken: req.csrfToken()
    });
  }

  const prefixes = ['shop', 'news', 'mail', 'temp', 'sign', 'deal'];
  let alias = null;
  let attempts = 0;
  const maxAttempts = 10;

  while (!alias && attempts < maxAttempts) {
    const prefix = prefixes[Math.floor(Math.random() * prefixes.length)];
    const number = Math.floor(Math.random() * 10000).toString().padStart(4, '0').slice(-2);
    const candidate = `${prefix}${number}@${process.env.DOMAIN}`;
    const existing = await Alias.findOne({ alias: candidate });
    if (!existing) {
      alias = candidate;
    }
    attempts++;
  }

  if (!alias) {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let candidate;
    do {
      candidate = Array(6).fill().map(() => chars[Math.floor(Math.random() * chars.length)]).join('');
      candidate = `${candidate}@${process.env.DOMAIN}`;
    } while (await Alias.findOne({ alias: candidate }));
    alias = candidate;
  }

  const newAlias = new Alias({ userId: user._id, alias, forwardTo: user.email, active: true, label });
  await newAlias.save();
  await User.updateOne({ _id: user._id }, { $inc: { aliasCount: 1 } });
  res.render('dashboard', {
    user,
    aliases: await Alias.find({ userId: user._id }),
    success: `Alias ${alias} created!`,
    csrfToken: req.csrfToken()
  });
});

// Toggle Spam Blocking
router.post('/toggle-spam/:id', isAuthenticated, async (req, res) => {
  const alias = await Alias.findOne({ _id: req.params.id, userId: req.user._id });
  if (alias) {
    await Alias.updateOne({ _id: req.params.id }, { blockSpam: !alias.blockSpam });
  }
  res.redirect('/dashboard');
});

// Delete Alias
router.post('/delete-alias/:id', isAuthenticated, async (req, res) => {
  const alias = await Alias.findOne({ _id: req.params.id, userId: req.user._id });
  if (alias) {
    await Alias.updateOne({ _id: req.params.id }, { active: false });
    await User.updateOne({ _id: req.user._id }, { $inc: { aliasCount: -1 } });
  }
  res.redirect('/dashboard');
});

// Subscribe
router.get('/subscribe', isAuthenticated, (req, res) => {
  res.render('subscribe', { user: req.user, csrfToken: req.csrfToken() });
});
router.post('/subscribe', isAuthenticated, async (req, res) => {
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ['card'],
    line_items: [{
      price: 'price_1XXXX', // Replace with your Stripe Price ID
      quantity: 1
    }],
    mode: 'subscription',
    client_reference_id: req.user._id.toString(),
    success_url: 'http://localhost:3000/dashboard',
    cancel_url: 'http://localhost:3000/subscribe'
  });
  res.redirect(session.url);
});

// Email Forwarding
router.post('/handle-email', async (req, res) => {
  const { from, to, subject, body } = req.body;
  const alias = await Alias.findOne({ alias: to[0], active: true });
  if (!alias || alias.blockSpam) return res.status(404).send('Alias not found or blocked');
  const params = {
    Source: from[0],
    Destination: { ToAddresses: [alias.forwardTo] },
    Message: {
      Subject: { Data: subject },
      Body: { Text: { Data: body } }
    }
  };
  await ses.sendEmail(params).promise();
  res.status(200).send('Email forwarded');
});

// Logout
router.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

module.exports = router;