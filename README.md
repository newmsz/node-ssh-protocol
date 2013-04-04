node-ssh-protocol
=================

Nodejs implementation of ssh protocol

Simple Usage
```
var fs = require('fs');
var ssh_protocol = require('ssh-protocol'),
	ssh_server = require('net').createServer().listen(22);

ssh_protocol.config({ 
	softwareversion: 'version_0.0',
	'ssh-rsa': { 
		publickey: fs.readFileSync('_t_rsa_b_2048.pub').toString(),
		privatekey: fs.readFileSync('_t_rsa_b_2048.key').toString() 
	},
	'banner': {
		message: 'banner messages...\r\n'
	}
});

ssh_protocol.on('userauth', function (request, response) {
	response.success('sole_user');
});

ssh_protocol.on('data', function (request, response) {
	response.stdout(request.data);
});

ssh_protocol.listen(ssh_server);
```