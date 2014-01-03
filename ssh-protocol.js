var	_ = require('underscore');
var SSH = require('./lib/ssh');

var default_config = { 
	softwareversion: 'nodesshprotocol_0.0.2', 
	comments: '',
	'ssh-rsa': null 
};

function SSHProtocol (conf) {
	this.config = _.defaults(conf, default_config);
	if(this.config['ssh-rsa']) {
		if(!this.config['ssh-rsa'].publickey) throw new Error('no publickey found in "ssh-rsa" configuration');
		if(!this.config['ssh-rsa'].privatekey) throw new Error('no privatekey found in "ssh-rsa" configuration');
		SSH.enableSSHRSA(this.config['ssh-rsa'].publickey, this.config['ssh-rsa'].privatekey); 
	}
	if(this.config['banner']) {
		SSH.setBanner(this.config['banner'].message, this.config['banner'].language);
	}
	if(this.config['authentication']) {
		SSH.setAuthenticationMethod(this.config['authentication']);
	}
}

module.exports = SSHProtocol;

require('util').inherits(SSHProtocol, require('events').EventEmitter);

SSHProtocol.prototype.listen = function (soc, cb) {
	soc.on('connection', _.bind(_onconnection, this));
};

function _onconnection(conn) {
	var ssh = new (SSH.SSH)(conn);
	ssh.hello(this.config.softwareversion, this.config.comments);
	this.emit('connection', ssh);
}