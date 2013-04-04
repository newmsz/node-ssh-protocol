var	_ = require('underscore');
var SSH = require('./lib/ssh');

var default_config = { 
	softwareversion: 'nodesshprotocol_0.0.1', 
	comments: '',
	'ssh-rsa': null 
};

var self = module.exports;

_.extend(self, new (require('events').EventEmitter)());

exports.config = function(conf) {
	config = _.defaults(conf, default_config);
	if(config['ssh-rsa']) {
		if(!config['ssh-rsa'].publickey) throw new Error('no publickey found in "ssh-rsa" configuration');
		if(!config['ssh-rsa'].privatekey) throw new Error('no privatekey found in "ssh-rsa" configuration');
		SSH.enableSSHRSA(config['ssh-rsa'].publickey, config['ssh-rsa'].privatekey); 
	}
	if(config['banner']) {
		SSH.setBanner(config['banner'].message, config['banner'].language);
	}
};

exports.listen = function (soc, cb) {
	soc.on('connection', _onconnection);
};

function _onconnection(conn) {
	var ssh = new (SSH.SSH)(conn);
	ssh.hello(config.softwareversion, config.comments);
	ssh.on('userauth', function (request, response) { self.emit('userauth', request, response); });
	ssh.on('data', function (request, response) { self.emit('data', request, response); });
}