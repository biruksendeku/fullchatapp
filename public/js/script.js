const socket = io();

const msgs = document.getElementById('msgs');
const input = document.getElementById('message');
const btn1 = document.getElementById('btn1');
const btn2 = document.getElementById('btn2');

socket.emit('user-connection');
appendMsg('You Joined');

socket.on('handle-user-connection', (name) => {
	appendMsg(`${name} Connected`);
});

socket.on('handle-send-message', (data) => {
	appendMsg(`${data.name}: ${data.message}`);
});

socket.on('handle-user-disconnection', (name) => {
	appendMsg(`${name} Disconnected`);
});

btn1.addEventListener('click', (e) => {
	e.preventDefault();
	const msg = input.value;
	appendMsg(`You: ${msg}`);
	const data = {
		name: null, // since we can overwrite it in backend
		message: msg
	};
	socket.emit('send-message', data);
	input.value = '';
});

btn2.addEventListener('click', (e) => {
	e.preventDefault();
	socket.emit('user-disconnection');
	window.location.href = "/";
});

function appendMsg(message) {
	const newDiv = document.createElement('div');
	newDiv.textContent = message;
	msgs.append(newDiv);
	msgs.scrollTop = msgs.scrollHeight;
};
