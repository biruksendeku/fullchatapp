const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const nodemailer = require('nodemailer');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const cors = require('cors');
const helmet = require('helmet');
const cron = require('node-cron');
require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const { createServer } = require('http');

const User = require('./models/user');

const app = express();
const port = process.env.PORT || 3000;
const publicFolder = path.join(__dirname, 'public');

const server = createServer(app);

const io = require('socket.io')(server);

// app settings
app.set('view engine', 'ejs');
app.set('view cache', false);

// built-in middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(publicFolder));
app.use(cors({
	origin: 'http://localhost:8000'
}));
app.use(session({
	secret: process.env.SESSION_SECRET_KEY,
	resave: false,
	saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(
	helmet.contentSecurityPolicy({
		directives: {
			defaultSrc: ["'self'"], // allow resource from the same origin
			scriptSrc: ["'self'"], // only self for script, I can add later
			styleSrc: ["'self'"], // allowing style only from my own
			imgSrc: ["'self'"] // allow image from my only
		},
	})
);
app.use(
	helmet({
		xPoweredBy: false, // disable the X-Powered-By header, for security
		frameguard: true, // I think this is true by default, but let's have it this way
	})
);

// custom middlewares
// NODEMAILER
const transporter = nodemailer.createTransport({
	service: 'Gmail',
	auth: {
		user: process.env.EMAIL_USER,
		pass: process.env.EMAIL_PASS
	}
});

const sendVerificationEmail = async (email, token) => {
	const verificationUrl = `${process.env.BASE_URL}/api/verify-email/${token}`;
	const mailOptions = {
		from: process.env.EMAIL_USER,
		to: email,
		subject: 'Verify Your Email',
		html: `
		<h1> Verify Your Email </h1>
		<p> Click on the link below to verify: </p>
		<a href="${verificationUrl}"> Verify Here </a>
		<p> This Link will expire in 24 hours. </p>
		`
	};
	await transporter.sendMail(mailOptions);
};

// cron job
cron.schedule('0 0 * * *', async () => {
	const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
	await User.deleteMany({
		isVerified: false,
		createdAt: { $lt: sevenDaysAgo }
	});
	console.log('7 Days old unverified users have been deleted');
});

// passport stuff
passport.use(new LocalStrategy(
	{
		usernameField: 'email',
		passwordField: 'password'
	},
	async (email, password, done) => {
		if(!email || !password) {
			return done(new Error('Bad Request - Missing Credentials'), null);
		}
		const user = await User.findOne({ email });
		if(!user) {
			return done(new Error('Bad Request - Incorrect email or password'), null);
		}
		const isValid = await bcrypt.compare(password, user.password);
		if(!isValid) {
			return done(new Error('Bad Request - Incorrect email or password'), null);
		}
		// successfully authenticated
		done(null, user);
	}
));

passport.serializeUser((user, done) => {
	try {
		done(null, user.id);
	} catch(err) {
		done(err, null);
	}
});

passport.deserializeUser(async (id, done) => {
	try {
		const user = await User.findById(id);
		if(!user) {
			return done(new Error('Bad Request - Invalid Credentials'), null);
		}
		// there's actually one
		done(null, user);
	} catch(err) {
		done(err, null);
	}
});

// socket.io stuff

// supporting middleware stuff
const isLoggedIn = (req, res, next) => {
	try {
		if(!req.isAuthenticated()) {
			return res.redirect('/login');
		}
		return next();
	} catch(err) {
		next(err);
	}
};

const loginLimiter = rateLimit({
	windowMs: 5 * 60 * 1000, // 5 minutes
	max: 10, // I guess 10 will do the job
	message: 'Too many request. Try again later.' // generic for security
});
app.use('/login', loginLimiter);
app.use('/signup', loginLimiter);

const apiLimiter = rateLimit({
	windowMs: 5 * 60 * 1000, // 5 minutes
	max: 15, // since there are more that 1 endpoints here
	message: 'Too many request. Try again later.'
});
app.use('/api', apiLimiter);

const normalLimiter = rateLimit({
	windowMs: 2 * 60 * 1000, // shorter time, shorter reformation
	max: 24, // 1 req per 5 second will do it
	message: 'Too many request. Try again later.'
});

// CRUD operation
app.get('/signup', (req, res, next) => {
	try {
		res.render('signup');
	} catch(err) {
		next(err);
	}
});

app.post('/signup', [
	body('name')
	.trim()
	.escape()
	.notEmpty()
	.withMessage('Invalid credentials, Name field required'),
	body('email')
	.trim()
	.escape()
	.notEmpty()
	.withMessage('Invalid credentials, Email field required')
	.isEmail()
	.normalizeEmail()
	.withMessage('Invalid email address, provide a valid email address'),
	body('password')
	.trim()
	.notEmpty()
	.withMessage('Invalid credentials, Password field required')
	.isLength({ min: 6 })
	.withMessage('Password length should be at least 6 characters long'),
	body('confirmPassword')
	.trim()
	.notEmpty()
	.withMessage('Invalid credentials, Confirm Password field required')
], async (req, res, next) => {
	const errors = validationResult(req);
	if(!errors.isEmpty()) {
		// return res.status(400).json({ errors: errors.array() });
		return next(new Error(errors.array() ));
	}
	try {
		const { name, email, password, confirmPassword } = req.body;
		if(!name || !email || !password || !confirmPassword) {
			return next(new Error('Bad Request - Missing Credentials'));
		}
		if(password !== confirmPassword) {
			return next(new Error('Bad Request - Password Mismatch'));
		}
		// db lookup
		const user = await User.findOne({ email });
		if(user) {
			// return res.redirect('/signup'); // poor ux
			return next(new Error('Bad Request - Incorrect email or password'));
		}
		// new user - grant account creation
		const verificationToken = crypto.randomBytes(32).toString('hex');
		const verificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 1 day plus

		const hashedPassword = await bcrypt.hash(password, 10);
		const name2 = name.charAt(0).toUpperCase() + name.slice(1).toLowerCase();
		
		const newUser = new User({
			name: name2,
			email,
			password: hashedPassword,
			verificationToken,
			verificationExpires
		});
		await newUser.save();
		await sendVerificationEmail(email, verificationToken);
		res.status(200).send('Registration Successful. Please check your email to verify your account.');
		
	} catch(err) {
		next(err);
	}
});

app.get('/api/verify-email/:token', async (req, res, next) => {
	try {
		const token = req.params.token.toString();
		const user = await User.findOne({
			verificationToken: token,
			verificationExpires: { $gt: Date.now() }
		});
		if(!user) {
			return res.status(400).send(`
			<h1> Invalid or Expired Verification Link. </h1>
			<p> This link is invalid or expired. </p>
			<a href="/api/resend-verification-link"> Request Resend <a/>
			`);
		};

		// there is user then
		user.isVerified = true;
		user.verifiedAt = Date.now();
		user.verificationToken = undefined;
		user.verificationExpires = undefined;
		// save the new user actions
		await user.save();
		// logging the user in
		req.login(user, (err) => {
			if(err) {
				return next(err);
			}
			res.redirect('/profile');
		});
		
	} catch(err) {
		next(err);
	}
});

app.get('/api/resend-verification-link', (req, res, next) => {
	try {
		res.render('resend.ejs')
	} catch(err) {
		next(err);
	}
});

app.post('/api/resend-verification-link', async (req, res, next) => {
	try {
		const { email } = req.body;
		const user = await User.findOne({
			email,
			isVerified: false
		});
		if(!user) {
			return res.status(400).send('Email not found or already verified');
		}
		// there's user
		const verificationToken = crypto.randomBytes(32).toString('hex');
		const verificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 1 day plus

		// save the new verification stuff
		user.verificationToken = verificationToken;
		user.verificationExpires = verificationExpires;
		await user.save();

		await sendVerificationEmail(email, verificationToken);
		res.status(200).send('Verification Link Sent. Please check your email to verify your account.');
		
	} catch(err) {
		next(err);
	}
});

app.get('/login', (req, res, next) => {
	try {
		res.render('login');
	} catch(err) {
		next(err);
	}
});

app.post('/login', passport.authenticate('local', {
	failureRedirect: '/login',
	successRedirect: '/profile'
}));

app.get('/profile', isLoggedIn, normalLimiter, (req, res, next) => {
	try {
		res.render('profile', {
			user: req.user
		});
	} catch(err) {
		next(err);
	}
});

app.get('/chat', isLoggedIn, async (req, res, next) => {
	try {
		const email = req.user.email;
		const user = await User.findOne({ email });
		io.on('connection', (socket) => {
			socket.on('user-connection', () => {
				socket.broadcast.emit('handle-user-connection', user.name);
			});
			socket.on('send-message', (data) => {
				data.name = user.name;
				socket.broadcast.emit('handle-send-message', data);
			});
			socket.on('user-disconnection', () => {
				socket.broadcast.emit('handle-user-disconnection', user.name);
			});
		});
		res.render('chat');
	} catch(err) {
		next(err);
	}
});

app.get('/logout', (req, res, next) => {
	try {
		req.logout((err) => {
			if(err) {
				return next(err);
			}
			res.redirect('/login');
		});
	} catch(err) {
		next(err);
	}
});

app.use((req, res, next) => {
	try {
		next(new Error('404 - Page Not Found'));
	} catch(err) {
		next(err);
	}
});

app.use((err, req, res, next) => {
	if(process.env.NODE_ENV  !== 'development') {
		console.log('Error Message: ', err.message);
		console.log('Error Stack: ', err.stack);
		return res.status(500).send('Internal Server Error');
	}
	res.json({ error: err.message }); // to make debugging a lil bit faster
});

// since we have socket.io
server.listen(port, () => {
	console.log(`Server listening on port ${port}...`);
});
