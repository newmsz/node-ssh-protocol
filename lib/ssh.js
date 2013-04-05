var crypto = require('crypto'),
	_ = require('underscore'),
	SSHTLP = require('./ssh-tlp'),
	SSHKex = require('./ssh-kex'),
	SSHUserAuth = require('./ssh-userauth');

var config;

function SSH (conn) {
	this._tlp = new SSHTLP(conn, this);
	this.on('message', this.onmessage);
}

require('util').inherits(SSH, require('events').EventEmitter);

exports.SSH = SSH;
exports.enableSSHRSA = enableSSHRSA;
exports.setBanner = SSHUserAuth.setBanner;
exports.setAuthenticationMethod = SSHUserAuth.setAuthenticationMethod; 

SSH.prototype.hello = function (softwareversion, comments) {
	this._tlp.hello(softwareversion, comments);
};

SSH.prototype.onmessage = function (msgno, payload) {
	console.log('yes!', msgno, payload);
};

function enableSSHRSA(publickey, privatekey) {
	SSHKex.enableSSHRSA(publickey, privatekey);
}

SSH.prototype._error = function (err) {
	console.error(this._state + ': ' + err.toString());
	this._conn.destroy();
};