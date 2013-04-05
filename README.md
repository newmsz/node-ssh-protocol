node-ssh-protocol
=================

Nodejs implementation of ssh protocol

Simple Usage
------------

```
var fs = require('fs');
var SSHProtocol = require('ssh-protocol'),
	SSHServer = require('net').createServer().listen(22);

var ssh = new SSHProtocol({ 
	softwareversion: 'version_is_0.0',
	'ssh-rsa': { 
		publickey: fs.readFileSync(...).toString(),
		privatekey: fs.readFileSync(...).toString() 
	},
	'banner': {
		message: 'banner...\r\n'
	}
});

ssh.on('connection', function (ssh_conn) {
	ssh_conn.on('terminal', function (request, response) {
		response.clear();
		response.stdout('Welcome, ' + this._mdc._user.Email + '!\r\n');
	});

	ssh_conn.on('authentication', function (request, response) {
		response.success();
	});
	
	ssh_conn.on('data', function (request, response) {
		response.stdout(request.data);
	});
});
	
ssh.listen(SSHServer);
```

Support Client
--------------
* Connection through OpenSSH is possible
* Connection through PuTTY is not yet supported. I don't understand how PuTTY do calculate kex hash...
 