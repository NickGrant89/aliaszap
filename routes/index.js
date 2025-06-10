const express = require('express');
const passport = require('passport');
const router = express.Router();
const User = require('../models/User');
const Alias = require('../models/Alias');
const CustomDomain = require('../models/CustomDomain');
const SupportTicket = require('../models/SupportTicket');
const AWS = require('aws-sdk');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const crypto = require('crypto');
const sanitizeHtml = require('sanitize-html');
const winston = require('winston');

// Configure AWS credentials
AWS.config.update({
  region: 'eu-west-2',
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});
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
  logger.info('Checking authentication:', { isAuthenticated: req.isAuthenticated(), user: req.user || 'No user' });
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
};

const isAdmin = (req, res, next) => {
  if (req.isAuthenticated() && req.user.isAdmin) {
    return next();
  }
  logger.info('Non-Admin User Attempted to Access Admin Route, Redirecting to /support:', { userId: req.user ? req.user._id.toString() : 'Unauthenticated', url: req.url });
  res.redirect('/support');
};

// Home
router.get('/', (req, res) => {
  res.render('index', { user: req.user });
});

// Login
router.get('/login', (req, res) => {
  res.render('login', { error: req.session.messages || null, csrfToken: req.csrfToken() });
});
// Login
router.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      logger.error('Login Error:', { message: err.message, stack: err.stack });
      return next(err);
    }
    if (!user) {
      return res.render('login', { error: info.message || 'Incorrect email or password.', csrfToken: req.csrfToken() });
    }
    req.login(user, (loginErr) => {
      if (loginErr) {
        logger.error('Login Session Error:', { message: loginErr.message, stack: loginErr.stack });
        return next(loginErr);
      }
      // Redirect based on user role
      if (user.isAdmin) {
        logger.info('Admin User Logged In, Redirecting to /admin/support-tickets:', { userId: user._id.toString() });
        return res.redirect('/admin/support-tickets');
      } else {
        logger.info('Regular User Logged In, Redirecting to /support:', { userId: user._id.toString() });
        return res.redirect('/dashboard');
      }
    });
  })(req, res, next);
});

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
  const { label, aliasLength, customAlias, expiresIn, customDomain } = req.body;
  logger.info('Create Alias Request:', { userId: user._id.toString(), label, aliasLength, customAlias, expiresIn, customDomain });
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
    let domain = process.env.DOMAIN;

    // Handle custom domain for Basic plan users
    if (user.plan !== 'free' && customDomain) {
      const customDomainDoc = await CustomDomain.findOne({ userId: user._id, domain: customDomain, verified: true });
      if (!customDomainDoc) {
        return res.render('dashboard', {
          user,
          activeAliases: await Alias.find({ userId: user._id, active: true }).lean(),
          inactiveAliases: await Alias.find({ userId: user._id, active: false }).lean(),
          error: 'Selected custom domain is not verified.',
          csrfToken: req.csrfToken()
        });
      }
      domain = customDomain;
    }

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
      const candidate = `${custom}@${domain}`;
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
          const candidate = `${prefix}${number}@${domain}`;
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
            candidate = `${candidate}@${domain}`;
          } while (await Alias.findOne({ alias: candidate }));
          alias = candidate;
        }
      } else {
        const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
        let candidate;
        do {
          candidate = Array(15).fill().map(() => chars[Math.floor(Math.random() * chars.length)]).join('');
          candidate = `${candidate}@${domain}`;
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

    const newAlias = new Alias({ userId: user._id, alias, forwardTo: user.email, active: true, label: sanitizedLabel, expiresAt, domain });
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
      logger.info('Reply Failed:', { aliasId: req.params.id, userId: user._id.toString(), reason: user.plan === 'free' ? 'Free plan' : 'Alias not found' });
      return res.render('dashboard', {
        user: req.user,
        activeAliases: await Alias.find({ userId: req.user._id, active: true }).lean(),
        inactiveAliases: await Alias.find({ userId: req.user._id, active: false }).lean(),
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

  logger.info('Received handle-email request:', { rawBody: req.body });

  if (!message || typeof message !== 'object') {
    logger.error('Invalid request body:', { body: req.body });
    return res.status(400).send('Invalid request body');
  }

  if (message.Type === 'SubscriptionConfirmation') {
    const subscribeUrl = message.SubscribeURL;
    if (subscribeUrl) {
      try {
        await fetch(subscribeUrl);
        logger.info('SNS Subscription Confirmed:', { subscribeUrl });
      } catch (err) {
        logger.error('Failed to Confirm SNS Subscription:', { subscribeUrl, error: err.message });
        return res.status(500).send('Failed to confirm subscription');
      }
    } else {
      logger.warn('No SubscribeURL in SubscriptionConfirmation message:', { message });
      return res.status(400).send('No SubscribeURL provided');
    }
    return res.status(200).send('Subscription confirmed');
  }

  if (message.Type === 'Notification') {
    if (!message.Message || !message.Message.mail) {
      logger.error('Invalid SES notification format:', { message: JSON.stringify(message, null, 2) });
      return res.status(400).send('Invalid SES notification format');
    }

    const mail = message.Message.mail;
    const content = message.Message.content ? message.Message.content.split('\n') : [];
    const from = [mail.source || 'support@aliaszap.com']; // Fallback to verified sender
    const to = mail.destination || [];
    const subject = mail.subject || (content.find(line => line.startsWith('Subject:'))?.split(': ')[1] || 'No Subject');
    const body = content.slice(content.findIndex(line => line.startsWith('Subject:')) + 1).join('\n').trim() || 'No Body';

    try {
      const alias = await Alias.findOne({ alias: to[0], active: true });
      if (!alias) {
        logger.info('Email Forwarding Failed:', { to: to[0], reason: 'Alias not found' });
        return res.status(404).send('Alias not found');
      }

      let isSpam = false;

      if (alias.blockSpam) {
        if (subject.toLowerCase().includes('spam') || body.toLowerCase().includes('unsubscribe')) {
          isSpam = true;
        }
      }

      if (alias.enableAdvancedSpamDetection) {
        const sender = from[0].toLowerCase();
        const senderDomain = sender.split('@')[1];
        if (alias.spamBlocklist.some(blocked => sender === blocked || senderDomain === blocked)) {
          isSpam = true;
          logger.info('Email Blocked by Custom Blocklist:', { sender, alias: alias.alias });
        }

        const spamKeywords = ['lottery', 'win a prize', 'free offer', 'click here', 'unsubscribe', 'viagra', 'casino'];
        const emailContent = `${subject} ${body}`.toLowerCase();
        if (spamKeywords.some(keyword => emailContent.includes(keyword))) {
          isSpam = true;
          logger.info('Email Flagged as Spam by Keywords:', { alias: alias.alias, subject });
        }
      }

      if (isSpam) {
        await Alias.updateOne({ _id: alias._id }, { $inc: { spamCount: 1, emailCount: 1 } });
        return res.status(200).send('Email blocked as spam');
      }

      await Alias.updateOne({ _id: alias._id }, { $inc: { emailCount: 1 } });

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
  } else {
    logger.error('Unsupported message type:', { message: JSON.stringify(message, null, 2) });
    return res.status(400).send('Unsupported message type');
  }
});

// Custom Domains Page
router.get('/custom-domains', isAuthenticated, async (req, res) => {
  try {
    if (req.user.plan === 'free') {
      return res.render('dashboard', {
        user: req.user,
        activeAliases: await Alias.find({ userId: req.user._id, active: true }).lean(),
        inactiveAliases: await Alias.find({ userId: req.user._id, active: false }).lean(),
        error: 'Upgrade to manage custom domains.',
        csrfToken: req.csrfToken()
      });
    }
    const domains = await CustomDomain.find({ userId: req.user._id }).lean();
    res.render('custom-domains', { user: req.user, domains, csrfToken: req.csrfToken() });
  } catch (err) {
    logger.error('Custom Domains Error:', err);
    res.render('dashboard', {
      user: req.user,
      activeAliases: await Alias.find({ userId: req.user._id, active: true }).lean(),
      inactiveAliases: await Alias.find({ userId: req.user._id, active: false }).lean(),
      error: 'Failed to load custom domains.',
      csrfToken: req.csrfToken()
    });
  }
});

// Add Custom Domain
router.post('/custom-domains', isAuthenticated, async (req, res) => {
  try {
    if (req.user.plan === 'free') {
      return res.render('dashboard', {
        user: req.user,
        activeAliases: await Alias.find({ userId: req.user._id, active: true }).lean(),
        inactiveAliases: await Alias.find({ userId: req.user._id, active: false }).lean(),
        error: 'Upgrade to manage custom domains.',
        csrfToken: req.csrfToken()
      });
    }
    const { domain } = req.body;
    const existingDomain = await CustomDomain.findOne({ domain, userId: req.user._id });
    if (existingDomain) {
      return res.render('custom-domains', {
        user: req.user,
        domains: await CustomDomain.find({ userId: req.user._id }).lean(),
        error: 'Domain already added.',
        csrfToken: req.csrfToken()
      });
    }
    const newDomain = new CustomDomain({ userId: req.user._id, domain });
    await newDomain.save();
    res.render('custom-domains', {
      user: req.user,
      domains: await CustomDomain.find({ userId: req.user._id }).lean(),
      success: `Added ${domain}. Please verify it by adding a TXT record.`,
      csrfToken: req.csrfToken()
    });
  } catch (err) {
    logger.error('Add Custom Domain Error:', err);
    res.render('custom-domains', {
      user: req.user,
      domains: await CustomDomain.find({ userId: req.user._id }).lean(),
      error: 'Failed to add custom domain.',
      csrfToken: req.csrfToken()
    });
  }
});

// Spam Settings Page
router.get('/spam-settings/:id', isAuthenticated, async (req, res) => {
  try {
    const alias = await Alias.findOne({ _id: req.params.id, userId: req.user._id, active: true });
    if (!alias) {
      return res.render('dashboard', {
        user: req.user,
        activeAliases: await Alias.find({ userId: req.user._id, active: true }).lean(),
        inactiveAliases: await Alias.find({ userId: req.user._id, active: false }).lean(),
        error: 'Alias not found.',
        csrfToken: req.csrfToken()
      });
    }
    res.render('spam-settings', { user: req.user, alias, csrfToken: req.csrfToken() });
  } catch (err) {
    logger.error('Spam Settings Error:', err);
    res.render('dashboard', {
      user: req.user,
      activeAliases: await Alias.find({ userId: req.user._id, active: true }).lean(),
      inactiveAliases: await Alias.find({ userId: req.user._id, active: false }).lean(),
      error: 'Failed to load spam settings.',
      csrfToken: req.csrfToken()
    });
  }
});

// Update Spam Settings
router.post('/spam-settings/:id', isAuthenticated, async (req, res) => {
  try {
    const alias = await Alias.findOne({ _id: req.params.id, userId: req.user._id, active: true });
    if (!alias) {
      return res.render('dashboard', {
        user: req.user,
        activeAliases: await Alias.find({ userId: req.user._id, active: true }).lean(),
        inactiveAliases: await Alias.find({ userId: req.user._id, active: false }).lean(),
        error: 'Alias not found.',
        csrfToken: req.csrfToken()
      });
    }

    const { blockSpam, enableAdvancedSpamDetection, blocklist } = req.body;
    alias.blockSpam = blockSpam === 'on';
    
    if (req.user.plan !== 'free') {
      alias.enableAdvancedSpamDetection = enableAdvancedSpamDetection === 'on';
      if (blocklist) {
        const blocklistArray = blocklist.split(',').map(item => item.trim().toLowerCase()).filter(item => item);
        alias.spamBlocklist = blocklistArray;
      } else {
        alias.spamBlocklist = [];
      }
    } else {
      alias.enableAdvancedSpamDetection = false;
      alias.spamBlocklist = [];
    }

    await alias.save();
    res.render('spam-settings', {
      user: req.user,
      alias,
      success: 'Spam settings updated successfully.',
      csrfToken: req.csrfToken()
    });
  } catch (err) {
    logger.error('Update Spam Settings Error:', err);
    res.render('spam-settings', {
      user: req.user,
      alias: await Alias.findOne({ _id: req.params.id, userId: req.user._id, active: true }),
      error: 'Failed to update spam settings.',
      csrfToken: req.csrfToken()
    });
  }
});

// Support Page
router.get('/support', isAuthenticated, async (req, res) => {
  try {
    const tickets = await SupportTicket.find({ userId: req.user._id }).lean();
    logger.info('Tickets fetched for support page:', { userId: req.user._id.toString(), tickets: tickets });
    res.render('support', { user: req.user, tickets, csrfToken: req.csrfToken() });
  } catch (err) {
    logger.error('Support Page Error:', { message: err.message, stack: err.stack });
    res.render('support', { user: req.user, tickets: [], error: 'Failed to load support tickets.', csrfToken: req.csrfToken() });
  }
});

// Submit Support Ticket
router.post('/support', isAuthenticated, async (req, res) => {
  const { user } = req;
  const { subject, message } = req.body;
  try {
    const sanitizedSubject = sanitizeHtml(subject, { allowedTags: [], allowedAttributes: {} });
    const sanitizedMessage = sanitizeHtml(message, { allowedTags: [], allowedAttributes: {} });

    if (!sanitizedSubject || !sanitizedMessage) {
      const tickets = await SupportTicket.find({ userId: user._id }).lean();
      return res.render('support', {
        user,
        tickets,
        error: 'Subject and message are required.',
        csrfToken: req.csrfToken()
      });
    }

    const ticket = new SupportTicket({
      userId: user._id,
      subject: sanitizedSubject,
      messages: [{ sender: 'user', message: sanitizedMessage }],
      priority: user.plan !== 'free'
    });
    await ticket.save();
    logger.info('Support Ticket Submitted:', { ticketId: ticket._id, userId: user._id.toString() });

    if (!process.env.ADMIN_EMAIL) {
      logger.error('Admin Email Not Configured:', { ticketId: ticket._id });
      throw new Error('ADMIN_EMAIL environment variable is not set');
    }

    const params = {
      Source: `support@aliaszap.com`,
      Destination: { ToAddresses: [process.env.ADMIN_EMAIL] },
      Message: {
        Subject: { Data: `New Support Ticket: ${sanitizedSubject}` },
        Body: {
          Text: {
            Data: `User: ${user.email}\nTicket ID: ${ticket._id}\nPriority: ${ticket.priority ? 'Yes' : 'No'}\nSubject: ${sanitizedSubject}\nMessage: ${sanitizedMessage}\nCreated At: ${ticket.createdAt.toISOString()}`
          }
        }
      }
    };
    await ses.sendEmail(params).promise();
    logger.info('Admin Notified of New Support Ticket:', { ticketId: ticket._id, adminEmail: process.env.ADMIN_EMAIL });

    const tickets = await SupportTicket.find({ userId: user._id }).lean();
    res.render('support', {
      user,
      tickets,
      success: 'Support ticket submitted successfully.',
      csrfToken: req.csrfToken()
    });
  } catch (err) {
    logger.error('Submit Support Ticket Error:', err.message, { stack: err.stack });
    const tickets = await SupportTicket.find({ userId: user._id }).lean();
    res.render('support', {
      user,
      tickets,
      error: 'Failed to submit support ticket: ' + err.message,
      csrfToken: req.csrfToken()
    });
  }
});

// User Reply to Support Ticket
router.post('/support/reply/:id', isAuthenticated, async (req, res) => {
  const { user } = req;
  const { message } = req.body;
  try {
    const sanitizedMessage = sanitizeHtml(message, { allowedTags: [], allowedAttributes: {} });
    if (!sanitizedMessage) {
      const tickets = await SupportTicket.find({ userId: user._id }).lean();
      return res.render('support', {
        user,
        tickets,
        error: 'Message is required.',
        csrfToken: req.csrfToken()
      });
    }

    const ticket = await SupportTicket.findOne({ _id: req.params.id, userId: user._id });
    if (!ticket) {
      const tickets = await SupportTicket.find({ userId: user._id }).lean();
      return res.render('support', {
        user,
        tickets,
        error: 'Ticket not found.',
        csrfToken: req.csrfToken()
      });
    }

    if (ticket.status === 'closed') {
      const tickets = await SupportTicket.find({ userId: user._id }).lean();
      return res.render('support', {
        user,
        tickets,
        error: 'Cannot reply to a closed ticket.',
        csrfToken: req.csrfToken()
      });
    }

    ticket.messages.push({ sender: 'user', message: sanitizedMessage });
    await ticket.save();
    logger.info('User Replied to Support Ticket:', { ticketId: ticket._id, userId: user._id.toString() });

    if (!process.env.ADMIN_EMAIL) {
      logger.error('Admin Email Not Configured:', { ticketId: ticket._id });
      throw new Error('ADMIN_EMAIL environment variable is not set');
    }

    const params = {
      Source: `support@aliaszap.com`,
      Destination: { ToAddresses: [process.env.ADMIN_EMAIL] },
      Message: {
        Subject: { Data: `New Reply to Support Ticket: ${ticket.subject}` },
        Body: {
          Text: {
            Data: `User: ${user.email}\nTicket ID: ${ticket._id}\nSubject: ${ticket.subject}\nReply: ${sanitizedMessage}\nTimestamp: ${new Date().toISOString()}`
          }
        }
      }
    };
    await ses.sendEmail(params).promise();
    logger.info('Admin Notified of User Reply:', { ticketId: ticket._id, adminEmail: process.env.ADMIN_EMAIL });

    const tickets = await SupportTicket.find({ userId: user._id }).lean();
    res.render('support', {
      user,
      tickets,
      success: 'Reply submitted successfully.',
      csrfToken: req.csrfToken()
    });
  } catch (err) {
    logger.error('User Reply to Support Ticket Error:', err.message, { stack: err.stack });
    const tickets = await SupportTicket.find({ userId: user._id }).lean();
    res.render('support', {
      user,
      tickets,
      error: 'Failed to submit reply: ' + err.message,
      csrfToken: req.csrfToken()
    });
  }
});

// Admin Support Tickets Dashboard
// Admin Support Tickets Dashboard
router.get('/admin/support-tickets', isAuthenticated, isAdmin, async (req, res) => {
  try {
    // Fetch tickets and handle invalid userId references
    const tickets = await SupportTicket.find().lean();
    // Populate user emails manually
    for (let ticket of tickets) {
      if (ticket.userId) {
        const user = await User.findById(ticket.userId).select('email').lean();
        ticket.userId = user || { email: 'Unknown User' };
      } else {
        ticket.userId = { email: 'Unknown User' };
      }
    }
    logger.info('Rendering admin/support-tickets with CSRF Token:', { token: req.csrfToken(), sessionID: req.sessionID });
    res.render('admin/support-tickets', { user: req.user, tickets, csrfToken: req.csrfToken() });
  } catch (err) {
    logger.error('Admin Support Tickets Error:', { message: err.message, stack: err.stack });
    res.render('admin/support-tickets', { user: req.user, tickets: [], error: 'Failed to load support tickets: ' + err.message, csrfToken: req.csrfToken() });
  }
});

// Admin Respond to Support Ticket
router.post('/admin/support-tickets/respond/:id', isAuthenticated, isAdmin, async (req, res) => {
  logger.info('Processing Admin Support Ticket Response:', { ticketId: req.params.id, sessionID: req.sessionID, userId: req.user._id.toString(), formData: req.body });
  const { response } = req.body;
  try {
    const sanitizedResponse = sanitizeHtml(response, { allowedTags: [], allowedAttributes: {} });
    if (!sanitizedResponse) {
      const tickets = await SupportTicket.find().lean();
      for (let ticket of tickets) {
        if (ticket.userId) {
          const user = await User.findById(ticket.userId).select('email').lean();
          ticket.userId = user || { email: 'Unknown User' };
        } else {
          ticket.userId = { email: 'Unknown User' };
        }
      }
      logger.info('Rendering admin/support-tickets with CSRF Token (Error: Response Required):', { token: req.csrfToken(), sessionID: req.sessionID });
      return res.render('admin/support-tickets', {
        user: req.user,
        tickets,
        error: 'Response is required.',
        csrfToken: req.csrfToken()
      });
    }

    const ticket = await SupportTicket.findById(req.params.id).populate('userId', 'email');
    if (!ticket) {
      const tickets = await SupportTicket.find().lean();
      for (let ticket of tickets) {
        if (ticket.userId) {
          const user = await User.findById(ticket.userId).select('email').lean();
          ticket.userId = user || { email: 'Unknown User' };
        } else {
          ticket.userId = { email: 'Unknown User' };
        }
      }
      logger.info('Rendering admin/support-tickets with CSRF Token (Error: Ticket Not Found):', { token: req.csrfToken(), sessionID: req.sessionID });
      return res.render('admin/support-tickets', {
        user: req.user,
        tickets,
        error: 'Ticket not found.',
        csrfToken: req.csrfToken()
      });
    }

    if (ticket.status === 'closed') {
      const tickets = await SupportTicket.find().lean();
      for (let ticket of tickets) {
        if (ticket.userId) {
          const user = await User.findById(ticket.userId).select('email').lean();
          ticket.userId = user || { email: 'Unknown User' };
        } else {
          ticket.userId = { email: 'Unknown User' };
        }
      }
      logger.info('Rendering admin/support-tickets with CSRF Token (Error: Cannot Respond to Closed Ticket):', { token: req.csrfToken(), sessionID: req.sessionID });
      return res.render('admin/support-tickets', {
        user: req.user,
        tickets,
        error: 'Cannot respond to a closed ticket.',
        csrfToken: req.csrfToken()
      });
    }

    ticket.messages.push({ sender: 'admin', message: sanitizedResponse });
    await ticket.save();
    logger.info('Admin Responded to Support Ticket:', { ticketId: ticket._id, userId: ticket.userId._id.toString() });

    const userEmail = ticket.userId.email;
    const params = {
      Source: `support@aliaszap.com`,
      Destination: { ToAddresses: [userEmail] },
      Message: {
        Subject: { Data: `Support Ticket Response: ${ticket.subject}` },
        Body: {
          Text: {
            Data: `Ticket ID: ${ticket._id}\nSubject: ${ticket.subject}\nAdmin Response: ${sanitizedResponse}\nResponded At: ${new Date().toISOString()}\n\nYou can view this ticket at: http://localhost:3000/support`
          }
        }
      }
    };
    await ses.sendEmail(params).promise();
    logger.info('User Notified of Support Ticket Response:', { ticketId: ticket._id, userEmail });

    const tickets = await SupportTicket.find().lean();
    for (let ticket of tickets) {
      if (ticket.userId) {
        const user = await User.findById(ticket.userId).select('email').lean();
        ticket.userId = user || { email: 'Unknown User' };
      } else {
        ticket.userId = { email: 'Unknown User' };
      }
    }
    logger.info('Rendering admin/support-tickets with CSRF Token (Success):', { token: req.csrfToken(), sessionID: req.sessionID });
    res.render('admin/support-tickets', {
      user: req.user,
      tickets,
      success: 'Response submitted and user notified.',
      csrfToken: req.csrfToken()
    });
  } catch (err) {
    logger.error('Respond to Support Ticket Error:', { message: err.message, stack: err.stack });
    const tickets = await SupportTicket.find().lean();
    for (let ticket of tickets) {
      if (ticket.userId) {
        const user = await User.findById(ticket.userId).select('email').lean();
        ticket.userId = user || { email: 'Unknown User' };
      } else {
        ticket.userId = { email: 'Unknown User' };
      }
    }
    logger.info('Rendering admin/support-tickets with CSRF Token (Error: Failed to Submit Response):', { token: req.csrfToken(), sessionID: req.sessionID });
    res.render('admin/support-tickets', {
      user: req.user,
      tickets,
      error: 'Failed to submit response: ' + err.message,
      csrfToken: req.csrfToken()
    });
  }
});

// Close Support Ticket
router.post('/admin/support-tickets/close/:id', isAuthenticated, isAdmin, async (req, res) => {
  try {
    const ticket = await SupportTicket.findById(req.params.id);
    if (!ticket) {
      const tickets = await SupportTicket.find().lean();
      for (let ticket of tickets) {
        if (ticket.userId) {
          const user = await User.findById(ticket.userId).select('email').lean();
          ticket.userId = user || { email: 'Unknown User' };
        } else {
          ticket.userId = { email: 'Unknown User' };
        }
      }
      return res.render('admin/support-tickets', {
        user: req.user,
        tickets,
        error: 'Ticket not found.',
        csrfToken: req.csrfToken()
      });
    }
    ticket.status = 'closed';
    await ticket.save();
    logger.info('Support Ticket Closed:', { ticketId: ticket._id, userId: ticket.userId.toString() });

    const tickets = await SupportTicket.find().lean();
    for (let ticket of tickets) {
      if (ticket.userId) {
        const user = await User.findById(ticket.userId).select('email').lean();
        ticket.userId = user || { email: 'Unknown User' };
      } else {
        ticket.userId = { email: 'Unknown User' };
      }
    }
    res.render('admin/support-tickets', {
      user: req.user,
      tickets,
      success: 'Ticket closed successfully.',
      csrfToken: req.csrfToken()
    });
  } catch (err) {
    logger.error('Close Support Ticket Error:', err);
    const tickets = await SupportTicket.find().lean();
    for (let ticket of tickets) {
      if (ticket.userId) {
        const user = await User.findById(ticket.userId).select('email').lean();
        ticket.userId = user || { email: 'Unknown User' };
      } else {
        ticket.userId = { email: 'Unknown User' };
      }
    }
    res.render('admin/support-tickets', {
      user: req.user,
      tickets,
      error: 'Failed to close ticket.',
      csrfToken: req.csrfToken()
    });
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