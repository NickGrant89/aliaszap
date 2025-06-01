const express = require('express');
const passport = require('passport');
const router = express.Router();
const User = require('../models/User');
const Alias = require('../models/Alias');
const AWS = require('aws-sdk');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const crypto = require('crypto');
const sanitizeHtml = require('sanitize-html');
const winston = require('winston');

AWS.config.update({ region: 'us-east-1' });
const ses = new AWS.SES();

// Logger setup (for consistency, though already in app.js)
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
    if (existingUser) {
      logger.info('Signup Failed: Email already exists', { email });
      return res.render('signup', { error: 'Email already exists.', csrfToken: req.csrfToken() });
    }
    const user = new User({ email, password });
    await user.save();
    logger.info('User Signed Up:', { email });
    req.login(user, () => res.redirect('/dashboard'));
  } catch (err) {
    logger.error('Signup Error:', err);
    res.render('signup', { error: 'Server error.', csrfToken: req.csrfToken() });
  }
});

// Dashboard
router.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    // Sync aliasCount with actual active aliases
    const activeCount = await Alias.countDocuments({ userId: req.user._id, active: true });
    if (req.user.aliasCount !== activeCount) {
      await User.updateOne({ _id: req.user._id }, { $set: { aliasCount: activeCount } });
      logger.info('Synced aliasCount for user:', { userId: req.user._id.toString(), aliasCount: activeCount });
      // Refresh user data
      req.user.aliasCount = activeCount;
    }

    const activeAliases = await Alias.find({ userId: req.user._id, active: true }).lean();
    const inactiveAliases = await Alias.find({ userId: req.user._id, active: false }).lean();
    logger.info('User ID:', req.user._id.toString());
    logger.info('Active Aliases:', { count: activeAliases.length, aliases: activeAliases.map(a => ({ alias: a.alias, userId: a.userId.toString() })) });
    logger.info('Inactive Aliases:', { count: inactiveAliases.length, aliases: inactiveAliases.map(a => ({ alias: a.alias, userId: a.userId.toString() })) });
    res.render('dashboard', { 
      user: req.user, 
      activeAliases: activeAliases || [], 
      inactiveAliases: inactiveAliases || [], 
      csrfToken: req.csrfToken() 
    });
  } catch (err) {
    logger.error('Dashboard Error:', err);
    res.render('dashboard', { 
      user: req.user, 
      activeAliases: [], 
      inactiveAliases: [], 
      error: 'Failed to load aliases', 
      csrfToken: req.csrfToken() 
    });
  }
});

// Create Alias
router.post('/create-alias', isAuthenticated, async (req, res) => {
  const { user } = req;
  const { label, aliasLength, customAlias, expiresIn } = req.body;
  logger.info('Create Alias Request:', { userId: user._id.toString(), label, aliasLength, customAlias, expiresIn });
  try {
    if (user.plan === 'free' && user.aliasCount >= 5) {
      logger.info('Create Alias Failed: Free plan limit reached');
      return res.render('dashboard', {
        user,
        activeAliases: await Alias.find({ userId: user._id, active: true }).lean(),
        inactiveAliases: await Alias.find({ userId: user._id, active: false }).lean(),
        error: 'Upgrade to create more aliases.',
        csrfToken: req.csrfToken()
      });
    }

    const sanitizedLabel = sanitizeHtml(label, {
      allowedTags: [],
      allowedAttributes: {}
    });

    let alias = null;
    if (user.plan !== 'free' && customAlias) {
      const custom = customAlias.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (custom.length < 3 || custom.length > 20) {
        logger.info('Create Alias Failed: Invalid custom alias length');
        return res.render('dashboard', {
          user,
          activeAliases: await Alias.find({ userId: user._id, active: true }).lean(),
          inactiveAliases: await Alias.find({ userId: user._id, active: false }).lean(),
          error: 'Custom alias must be 3-20 characters (letters and numbers only).',
          csrfToken: req.csrfToken()
        });
      }
      const candidate = `${custom}@${process.env.DOMAIN}`;
      const existing = await Alias.findOne({ alias: candidate });
      if (existing) {
        logger.info('Create Alias Failed: Custom alias already exists');
        return res.render('dashboard', {
          user,
          activeAliases: await Alias.find({ userId: user._id, active: true }).lean(),
          inactiveAliases: await Alias.find({ userId: user._id, active: false }).lean(),
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

    let expiresAt = null;
    if (expiresIn === '1day') {
      expiresAt = new Date(Date.now() + 1 * 24 * 60 * 60 * 1000);
    } else if (expiresIn === '7days') {
      expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    } else if (expiresIn === '30days') {
      expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    }

    const newAlias = new Alias({ userId: user._id, alias, forwardTo: user.email, active: true, label: sanitizedLabel, expiresAt });
    await newAlias.save();
    await User.updateOne({ _id: user._id }, { $inc: { aliasCount: 1 } });
    logger.info('Alias Created:', { alias, userId: user._id.toString() });

    if (req.headers['content-type'] === 'application/json') {
      return res.json({ success: true, alias });
    }

    res.render('dashboard', {
      user,
      activeAliases: await Alias.find({ userId: user._id, active: true }).lean(),
      inactiveAliases: await Alias.find({ userId: user._id, active: false }).lean(),
      success: `Alias ${alias} created!`,
      csrfToken: req.csrfToken()
    });
  } catch (err) {
    logger.error('Create Alias Error:', err);
    res.render('dashboard', {
      user,
      activeAliases: await Alias.find({ userId: user._id, active: true }).lean(),
      inactiveAliases: await Alias.find({ userId: user._id, active: false }).lean(),
      error: 'Failed to create alias.',
      csrfToken: req.csrfToken()
    });
  }
});

// Toggle Spam Blocking
router.post('/toggle-spam/:id', isAuthenticated, async (req, res) => {
  try {
    const alias = await Alias.findOne({ _id: req.params.id, userId: req.user._id });
    if (alias) {
      await Alias.updateOne({ _id: req.params.id }, { blockSpam: !alias.blockSpam });
      logger.info('Toggled Spam for Alias:', { aliasId: req.params.id, blockSpam: !alias.blockSpam });
    } else {
      logger.info('Toggle Spam Failed: Alias not found', { aliasId: req.params.id });
    }
    res.redirect('/dashboard');
  } catch (err) {
    logger.error('Toggle Spam Error:', err);
    res.redirect('/dashboard');
  }
});

// Delete Alias
router.post('/delete-alias/:id', isAuthenticated, async (req, res) => {
  try {
    logger.info('Delete Alias Request:', { aliasId: req.params.id, userId: req.user._id.toString(), csrfToken: req.body._csrf });
    const alias = await Alias.findOne({ _id: req.params.id, userId: req.user._id });
    if (!alias) {
      logger.info('Delete Alias Failed: Alias not found', { aliasId: req.params.id, userId: req.user._id.toString() });
      return res.render('dashboard', {
        user: req.user,
        activeAliases: await Alias.find({ userId: req.user._id, active: true }).lean(),
        inactiveAliases: await Alias.find({ userId: req.user._id, active: false }).lean(),
        error: 'Alias not found.',
        csrfToken: req.csrfToken()
      });
    }
    await Alias.updateOne({ _id: req.params.id }, { active: false });
    await User.updateOne({ _id: req.user._id }, { $inc: { aliasCount: -1 } });
    logger.info('Alias Deleted:', { aliasId: req.params.id, userId: req.user._id.toString() });
    res.render('dashboard', { 
      user: req.user, 
      activeAliases: await Alias.find({ userId: req.user._id, active: true }).lean(),
      inactiveAliases: await Alias.find({ userId: req.user._id, active: false }).lean(),
      success: 'Alias deleted successfully.',
      csrfToken: req.csrfToken() 
    });
  } catch (err) {
    logger.error('Delete Alias Error:', err);
    res.render('dashboard', {
      user: req.user,
      activeAliases: await Alias.find({ userId: req.user._id, active: true }).lean(),
      inactiveAliases: await Alias.find({ userId: req.user._id, active: false }).lean(),
      error: 'Failed to delete alias.',
      csrfToken: req.csrfToken()
    });
  }
});

// Reply from Alias
router.get('/reply/:id', isAuthenticated, async (req, res) => {
  try {
    const alias = await Alias.findOne({ _id: req.params.id, userId: req.user._id, active: true });
    if (!alias || req.user.plan === 'free') {
      logger.info('Reply Failed:', { aliasId: req.params.id, userId: req.user._id.toString(), reason: req.user.plan === 'free' ? 'Free plan' : 'Alias not found' });
      return res.render('dashboard', {
        user: req.user,
        activeAliases: await Alias.find({ userId: req.user._id, active: true }).lean(),
        inactiveAliases: await Alias.find({ userId: req.user._id, active: false }).lean(),
        error: req.user.plan === 'free' ? 'Upgrade to reply using aliases.' : 'Alias not found.',
        csrfToken: req.csrfToken()
      });
    }
    res.render('reply', { user: req.user, alias, csrfToken: req.csrfToken() });
  } catch (err) {
    logger.error('Reply Get Error:', err);
    res.render('dashboard', {
      user: req.user,
      activeAliases: await Alias.find({ userId: req.user._id, active: true }).lean(),
      inactiveAliases: await Alias.find({ userId: req.user._id, active: false }).lean(),
      error: 'Failed to load reply form.',
      csrfToken: req.csrfToken()
    });
  }
});

router.post('/reply/:id', isAuthenticated, async (req, res) => {
  const { user } = req;
  const { subject, body, to } = req.body;
  try {
    const alias = await Alias.findOne({ _id: req.params.id, userId: user._id, active: true });
    if (!alias || user.plan === 'free') {
      logger.info('Reply Post Failed:', { aliasId: req.params.id, userId: user._id.toString(), reason: user.plan === 'free' ? 'Free plan' : 'Alias not found' });
      return res.render('dashboard', {
        user,
        activeAliases: await Alias.find({ userId: user._id, active: true }).lean(),
        inactiveAliases: await Alias.find({ userId: user._id, active: false }).lean(),
        error: user.plan === 'free' ? 'Upgrade to reply using aliases.' : 'Alias not found.',
        csrfToken: req.csrfToken()
      });
    }

    const params = {
      Source: alias.alias,
      Destination: { ToAddresses: [to] },
      Message: {
        Subject: { Data: subject },
        Body: { Text: { Data: body } }
      }
    };
    await ses.sendEmail(params).promise();
    logger.info('Reply Sent:', { aliasId: req.params.id, userId: user._id.toString(), to });
    res.render('dashboard', {
      user,
      activeAliases: await Alias.find({ userId: user._id, active: true }).lean(),
      inactiveAliases: await Alias.find({ userId: user._id, active: false }).lean(),
      success: `Reply sent from ${alias.alias}!`,
      csrfToken: req.csrfToken()
    });
  } catch (err) {
    logger.error('SES Reply Error:', err);
    res.render('dashboard', {
      user,
      activeAliases: await Alias.find({ userId: user._id, active: true }).lean(),
      inactiveAliases: await Alias.find({ userId: user._id, active: false }).lean(),
      error: `Failed to send reply: ${err.message}`,
      csrfToken: req.csrfToken()
    });
  }
});

// Subscribe
router.get('/subscribe', isAuthenticated, (req, res) => {
  res.render('subscribe', { user: req.user, csrfToken: req.csrfToken() });
});
router.post('/subscribe', isAuthenticated, async (req, res) => {
  try {
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
    logger.info('Subscription Session Created:', { userId: req.user._id.toString(), sessionId: session.id });
    res.redirect(session.url);
  } catch (err) {
    logger.error('Subscribe Error:', err);
    res.render('subscribe', { user: req.user, error: 'Failed to initiate subscription.', csrfToken: req.csrfToken() });
  }
});

// Email Forwarding
router.post('/handle-email', async (req, res) => {
  const message = req.body;

  if (message.Type === 'SubscriptionConfirmation' || message.Type === 'Notification') {
    const signature = message.Signature;
    const signatureVersion = message.SignatureVersion;
    const signingCertURL = message.SigningCertURL;
    const messageBody = JSON.stringify({
      Message: message.Message,
      MessageId: message.MessageId,
      Subject: message.Subject || '',
      Timestamp: message.Timestamp,
      TopicArn: message.TopicArn,
      Type: message.Type
    });

    const certResponse = await fetch(signingCertURL);
    const cert = await certResponse.text();

    const verifier = crypto.createVerify('sha1WithRSAEncryption');
    verifier.update(messageBody);
    const isValid = verifier.verify(cert, signature, 'base64');

    if (!isValid) {
      logger.error('Invalid SNS signature');
      return res.status(403).send('Invalid SNS signature');
    }
  }

  if (message.Type === 'SubscriptionConfirmation') {
    const subscribeUrl = message.SubscribeURL;
    await fetch(subscribeUrl);
    logger.info('SNS Subscription Confirmed:', { subscribeUrl });
    return res.status(200).send('Subscription confirmed');
  }

  const { from, to, subject, body } = message;
  try {
    const alias = await Alias.findOne({ alias: to[0], active: true });
    if (!alias || alias.blockSpam) {
      logger.info('Email Forwarding Failed:', { to: to[0], reason: !alias ? 'Alias not found' : 'Spam blocked' });
      return res.status(404).send('Alias not found or blocked');
    }

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
    logger.info('Email Forwarded:', { from: from[0], to: alias.forwardTo });
    res.status(200).send('Email forwarded');
  } catch (err) {
    logger.error('SES Forwarding Error:', err);
    res.status(500).send('Failed to forward email');
  }
});

// Test Tabs
router.get('/test-tabs', (req, res) => {
  res.render('test-tabs');
});

// Logout
router.get('/logout', (req, res) => {
  logger.info('User Logged Out:', { userId: req.user ? req.user._id.toString() : 'Unknown' });
  req.logout(() => res.redirect('/'));
});

module.exports = router;