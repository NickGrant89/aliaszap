const express = require('express');
const passport = require('passport');
const router = express.Router();
const User = require('../models/User');
const Alias = require('../models/Alias');
const AWS = require('aws-sdk');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

AWS.config.update({ region: 'us-east-1' });
const ses = new AWS.SES();

// Middleware: Define isAuthenticated at the top
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
  const activeAliases = await Alias.find({ userId: req.user._id, active: true });
  const inactiveAliases = await Alias.find({ userId: req.user._id, active: false });
  res.render('dashboard', { user: req.user, activeAliases, inactiveAliases, csrfToken: req.csrfToken() });
});

// Create Alias
router.post('/create-alias', isAuthenticated, async (req, res) => {
  const { user } = req;
  const { label, aliasLength, customAlias, expiresIn } = req.body;
  if (user.plan === 'free' && user.aliasCount >= 5) {
    return res.render('dashboard', {
      user,
      activeAliases: await Alias.find({ userId: user._id, active: true }),
      inactiveAliases: await Alias.find({ userId: user._id, active: false }),
      error: 'Upgrade to create more aliases.',
      csrfToken: req.csrfToken()
    });
  }

  let alias = null;
  if (user.plan !== 'free' && customAlias) {
    const custom = customAlias.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (custom.length < 3 || custom.length > 20) {
      return res.render('dashboard', {
        user,
        activeAliases: await Alias.find({ userId: user._id, active: true }),
        inactiveAliases: await Alias.find({ userId: user._id, active: false }),
        error: 'Custom alias must be 3-20 characters (letters and numbers only).',
        csrfToken: req.csrfToken()
      });
    }
    const candidate = `${custom}@${process.env.DOMAIN}`;
    const existing = await Alias.findOne({ alias: candidate });
    if (existing) {
      return res.render('dashboard', {
        user,
        activeAliases: await Alias.find({ userId: user._id, active: true }),
        inactiveAliases: await Alias.find({ userId: user._id, active: false }),
        error: 'Custom alias already exists.',
        csrfToken: req.csrfToken()
      });
    }
    alias = candidate;
  } else {
    if (aliasLength === 'short') {
      const prefixes = ['shop', 'news', 'mail', 'temp', 'sign', 'deal'];
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
    } else {
      const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
      let candidate;
      do {
        candidate = Array(15).fill().map(() => chars[Math.floor(Math.random() * chars.length)]).join('');
        candidate = `${candidate}@${process.env.DOMAIN}`;
      } while (await Alias.findOne({ alias: candidate }));
      alias = candidate;
    }
  }

  // Set expiration date based on user selection
  let expiresAt = null;
  if (expiresIn === '1day') {
    expiresAt = new Date(Date.now() + 1 * 24 * 60 * 60 * 1000); // 1 day
  } else if (expiresIn === '7days') {
    expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
  } else if (expiresIn === '30days') {
    expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
  }

  const newAlias = new Alias({ userId: user._id, alias, forwardTo: user.email, active: true, label, expiresAt });
  await newAlias.save();
  await User.updateOne({ _id: user._id }, { $inc: { aliasCount: 1 } });

  // Return JSON for extension
  if (req.headers['content-type'] === 'application/json') {
    return res.json({ success: true, alias });
  }

  res.render('dashboard', {
    user,
    activeAliases: await Alias.find({ userId: user._id, active: true }),
    inactiveAliases: await Alias.find({ userId: user._id, active: false }),
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

// Reply from Alias
router.get('/reply/:id', isAuthenticated, async (req, res) => {
  const alias = await Alias.findOne({ _id: req.params.id, userId: req.user._id, active: true });
  if (!alias || req.user.plan === 'free') {
    return res.render('dashboard', {
      user: req.user,
      activeAliases: await Alias.find({ userId: req.user._id, active: true }),
      inactiveAliases: await Alias.find({ userId: req.user._id, active: false }),
      error: req.user.plan === 'free' ? 'Upgrade to reply using aliases.' : 'Alias not found.',
      csrfToken: req.csrfToken()
    });
  }
  res.render('reply', { user: req.user, alias, csrfToken: req.csrfToken() });
});

router.post('/reply/:id', isAuthenticated, async (req, res) => {
  const { user } = req;
  const { subject, body, to } = req.body;
  const alias = await Alias.findOne({ _id: req.params.id, userId: user._id, active: true });
  if (!alias || user.plan === 'free') {
    return res.render('dashboard', {
      user,
      activeAliases: await Alias.find({ userId: user._id, active: true }),
      inactiveAliases: await Alias.find({ userId: user._id, active: false }),
      error: user.plan === 'free' ? 'Upgrade to reply using aliases.' : 'Alias not found.',
      csrfToken: req.csrfToken()
    });
  }

  const params = {
    Source: alias.alias, // Reply from the alias
    Destination: { ToAddresses: [to] },
    Message: {
      Subject: { Data: subject },
      Body: { Text: { Data: body } }
    }
  };
  await ses.sendEmail(params).promise();
  res.render('dashboard', {
    user,
    activeAliases: await Alias.find({ userId: user._id, active: true }),
    inactiveAliases: await Alias.find({ userId: user._id, active: false }),
    success: `Reply sent from ${alias.alias}!`,
    csrfToken: req.csrfToken()
  });
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
  const message = req.body;
  if (message.Type === 'SubscriptionConfirmation') {
    const subscribeUrl = message.SubscribeURL;
    await fetch(subscribeUrl);
    return res.status(200).send('Subscription confirmed');
  }

  const { from, to, subject, body } = message;
  const alias = await Alias.findOne({ alias: to[0], active: true });
  if (!alias || alias.blockSpam) return res.status(404).send('Alias not found or blocked');

  const update = { $inc: { emailCount: 1 } };
  if (subject.toLowerCase().includes('spam') || body.toLowerCase().includes('unsubscribe')) {
    update.$inc.spamCount = 1;
  }
  await Alias.updateOne({ _id: alias._id }, update);

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