const mongoose = require('mongoose');
const { isEmail } = require('validator');
require('dotenv').config();

mongoose.connect(process.env.MONGODB_URI)
.then(() => {
	console.log('Database Connected');
})
.catch((err) => {
	console.log('Failed to connect to DB: ', err.message);
	process.exit(1); // if it fails, it's better to stop the app!!
});

const userSchema = new mongoose.Schema({
	name: {
		type: String,
		required: [ true, 'Name field is required' ],
	},
	email: {
		type: String,
		unique: true,
		index: true, // for faster lookup
		required: [ true, 'Email field is required' ],
		lowercase: true,
		validate: [ isEmail, 'Invalid email address' ]
	},
	password: {
		type: String,
		required: [ true, 'Password field is required' ],
		minlength: [ 6, 'Password length should be at least 6 characters long' ]
	},
	isVerified: {
		type: Boolean,
		default: false
	},
	verifiedAt: {
		type: Date,
		default: null
	},
	verificationToken: String,
	verificationExpires: Date,
	createdAt: {
		type: Date,
		default: Date.now()
	}
});

module.exports = mongoose.model('User', userSchema);
