var crypto = require('crypto'),
	_ = require('underscore');
var SSHPacket = require('./ssh-packet'),
	SSHKex = require('./ssh-kex');
     
var state = {
	AUTHENTICATION_BEGIN: 'AUTHENTICATION_BEGIN',	
};
         
var MESSAGE_NUMBER = { 
	SSH_MSG_USERAUTH_REQUEST: 50, 			/* RFC 4252 SSH Authentication Protocol Section 6 */
	SSH_MSG_USERAUTH_FAILURE: 51,			/* RFC 4252 SSH Authentication Protocol Section 6 */
	SSH_MSG_USERAUTH_SUCCESS: 52,			/* RFC 4252 SSH Authentication Protocol Section 6 */
	SSH_MSG_USERAUTH_BANNER: 53,			/* RFC 4252 SSH Authentication Protocol Section 6 */
	SSH_MSG_USERAUTH_PK_OK: 60,				/* RFC 4252 SSH Authentication Protocol Section 7 */
	SSH_MSG_USERAUTH_PASSWD_CHANGEREQ: 60	/* RFC 4252 SSH Authentication Protocol Section 8 */
};

var AVAILABLE_METHODS = [/*'publickey',*/ 'password'];
var _BANNER = null;

function SSHUserAuth() {
	this.userAuthenticated = false;

	this._didISendBanner = false;
	this._onuserauth = null;
	
	this._userinfo = null;
	this._username = this._servicename = this._method = null;
	this._pk_algorithm_name = this._pk_blob = null;	
}

exports.SSHUserAuth = SSHUserAuth;
exports.setBanner = setBanner;

SSHUserAuth.prototype.getUserInfo = function () {
	return {
		userinfo: this._userinfo,
		sshuser: {
			username: this._username,
		}
	};
};

SSHUserAuth.prototype.authenticate = function (packet, cb) {
	var payload = packet.readBinaryPacket();
	if(packet.disconnect_msg) return;
	if(!payload) return;
	var msgno = payload.readUInt8(0),
		payload = payload.slice(1, payload.length);
		
	if(!this.userAuthenticated) {
		if(!this._didISendBanner && _BANNER) {
			cb(null, packet.createBinaryPacket(MESSAGE_NUMBER.SSH_MSG_USERAUTH_BANNER, _BANNER));
			this._didISendBanner = true;
		}
		
		this._verifyAuthenticationRequest(payload, _.bind(function (err, output, msgno) {
			if(Buffer.isBuffer(output)) { 
				output = packet.createBinaryPacket(msgno, output);
				return cb(null, output);		  
			} else if (output == -1) { /* unintended error in authentication */
				var list = SSHPacket.createNameList(['none']);
					partial_success = new Buffer(1);
				partial_success.writeUInt8(0, 0);
				output = Buffer.concat([list, partial_success], list.length + 1);
				output = packet.createBinaryPacket(MESSAGE_NUMBER.SSH_MSG_USERAUTH_FAILURE, output);
				
				return cb(null, output);
			} else if(output === undefined) { /* success */
				output = packet.createBinaryPacket(MESSAGE_NUMBER.SSH_MSG_USERAUTH_SUCCESS, new Buffer(0));
				this.userAuthenticated = true;
				return cb(null, output);
			}
		}, this));
	} else
		throw new Error('the user has already authenticated');	
};

SSHUserAuth.prototype.onUserAuth = function (cb) {
	this._onuserauth = cb;
};

SSHUserAuth.prototype._verifyAuthenticationRequest = function (payload, cb) {
	var user, service, method;
	user = SSHPacket.readString(payload)
	payload = payload.slice(user.offset, payload.length);
	user = user.string.toString('utf8');
	service = SSHPacket.readString(payload)
	payload = payload.slice(service.offset, payload.length);
	service = service.string.toString('ascii');
	method = SSHPacket.readString(payload);
	payload = payload.slice(method.offset, payload.length);
	method = method.string.toString('ascii');
	
	if(this._username && this._username !== user) return cb(null, -1);
	if(this._servicename && this._servicename !== service) return cb(null, -1);
	if(this._method && this._method !== 'none' && this._method !== method) return cb(null, -1);
	
	this._username = user;
	this._servicename = service;
	this._method = method;
	 
	switch(method) {
	case 'none':
		var partial_success = new Buffer(1),
			output = SSHPacket.createNameList(AVAILABLE_METHODS);
		partial_success.writeUInt8(1, 0);
		output = Buffer.concat([output, partial_success], output.length + 1); 
		return cb(null, output, MESSAGE_NUMBER.SSH_MSG_USERAUTH_FAILURE);
		
	case 'publickey':
		var has_signature = payload.readUInt8(0);
		payload = payload.slice(1, payload.length)
		
		var alg_name = SSHPacket.readString(payload);
		payload = payload.slice(alg_name.offset, payload.length);
		alg_name = alg_name.string.toString('ascii');
		var blob = SSHPacket.readString(payload);
		payload = payload.slice(blob.offset, payload.length);
		blob = blob.string;
		
		if(alg_name !== 'ssh-rsa') return cb(null, -1);
		
		if(this._pk_algorithm_name && this._pk_algorithm_name !== alg_name) return cb(null, -1);
		if(this._pk_blob && this._pk_blob.toString('hex') !== blob.toString('hex')) return cb(null, -1);
	
		this._pk_algorithm_name = alg_name; 
		this._pk_blob = blob;
		this._pk = SSHKex.verifySSHRSAPublicKey(this._pk_blob);
		
		if(!has_signature) {
			alg_name = SSHPacket.createString(new Buffer(alg_name, 'ascii'));
			blob = SSHPacket.createString(blob);
			return cb(null, Buffer.concat([alg_name, blob], alg_name.length + blob.length), MESSAGE_NUMBER.SSH_MSG_USERAUTH_PK_OK);
		} 
		
		//TODO: implement below
		var verifyf = this._verifyf(),
			signature = SSHPacket.readString(payload).string;
			
		verifyf.update(signature);
		if(verifyf.verify(SSH2_to_PEM(this._pk_blob), signature)) {
			
		} else
			return cb(null, -1);
		break;
	case 'password':
		if(payload.readUInt8(0) === 0) { // not PASSWD_CHANGEREQ
			var password = SSHPacket.readString(payload.slice(1, payload.length)).string.toString('utf8');
			if(!this._onuserauth) return cb(null, -1);
			
			this._onuserauth({
				method: 'password',
				username: this._username,
				password: password
			}, {
				success: _.bind(function (userinfo) {
					this._userinfo = userinfo;
					return cb();
				}, this),
				fail: function () {
					return cb(null, SSHPacket.createNameList(AVAILABLE_METHODS));
				},
			});
		} else {
		}
		break;
	default: throw new Error('unknown method: ' + method);
	}
};

SSHUserAuth.prototype._verifyf = function () {
	switch(this._pk_algorithm_name) {
	case 'ssh-rsa': return crypto.createVerify('RSA-SHA1');	
	}
};

function SSH2_to_PEM(ssh2_formatted) {
	//TODO: implement this
	return ssh_formatted;
};

function setBanner(msg, lang) {
	lang = SSHPacket.createString(new Buffer(lang || 'en', 'utf8'));
	msg = SSHPacket.createString(new Buffer(msg, 'utf8'));
	_BANNER = Buffer.concat([msg, lang], msg.length + lang.length);
}