const express = require('express');

const app = express();
const port = 3000;

const User = require('./models/user');

async function loadAllUsers() {
	const users = await User.find({});
	console.log(users);
};
loadAllUsers();

app.delete('/user/:id', async (req, res) => {
	await User.findByIdAndDelete(req.params.id)
	.then(() => {
		res.status(200).send('Deleted Successfully');
	})
	.catch((err) => {
		res.status(500).send('Failed to delete');
	});
});

app.listen(port, () => {
	console.log(`Server listening on port ${port}...`);
});
