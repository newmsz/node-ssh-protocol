var crypto = require('crypto'),
	_ = require('underscore');
var SSHPacket = require('./ssh-packet'),
	SSHKex = require('./ssh-kex'),
	SSHUserAuth = require('./ssh-userauth'),
	SSHChannel = require('./ssh-channel');

var state = {
	PROTOCOL_VERSION_EXCHANGE: 'PROTOCOL_VERSION_EXCHANGE', 
	KEX: 'KEX',
	SERVICE_REQUEST: 'SERVICE_REQUEST',
	USER_AUTH: 'USER_AUTH',
	CHANNEL: 'CHANNEL'
};

function TLP (conn, al) {
	this._conn = conn;
	this._al = al;
	
	this._conn.on('data', _.bind(function (buf) {
		this._packet.append(buf);
		this._process();	
	}, this));
	this._state = state.PROTOCOL_VERSION_EXCHANGE;
	
	this._packet = new SSHPacket.SSHPacket();
	this._kex = new SSHKex.SSHKex();
	this._user = new SSHUserAuth.SSHUserAuth();
	this._eventForward('authentication', this._user); 
	this._channel = new SSHChannel.SSHChannel();
	this._eventForward('terminal', this._channel);
	this._eventForward('data', this._channel);
}

var MESSAGE_NUMBER = {
	SSH_MSG_SERVICE_REQUEST: 5, 			/* RFC 4253 SSH Transport Layer Protocol Section 12 */
	SSH_MSG_SERVICE_ACCEPT: 6, 				/* RFC 4253 SSH Transport Layer Protocol Section 12 */
};

module.exports = TLP;

TLP.prototype._eventForward = function (evt, obj) {
	obj.on(evt, _.bind(function () {
		arguments = Array.prototype.slice.call(arguments);
		arguments.unshift(evt);
		this._al.emit.apply(this._al, arguments); 
	}, this));
};

TLP.prototype._process = function () {
	switch(this._state) {
	case state.PROTOCOL_VERSION_EXCHANGE:
		this._exchangeProtocolVersion(this._packet);
		this._state = state.KEX
		if(this._packet.eob()) break;
	case state.KEX:
		if(!this._packet.isReadable) return;
		
		this._kex.exchangeKeys(this._packet, _.bind(function (err, out) {
			if(this._kex.keyExchanged) {
				this._packet.attachKeyFunctions(
						this._kex.recvhashsize(), this._kex.recvblocksize(), this._kex.recvhmacf(), this._kex.decipherf(),
						this._kex.sendhashsize(), this._kex.sendblocksize(), this._kex.sendhmacf(), this._kex.cipherf()); 
				this._state = state.SERVICE_REQUEST;
			}
			
			this._packet.trim();
			this._conn.write(out);
		}, this));
		
		break;
	case state.SERVICE_REQUEST:
		if(!this._packet.isReadable) return;		
		
		var payload = this._packet.readBinaryPacket();
		if(this._packet.disconnect_msg) return this._disconnect(this._packet.disconnect_msg);
		else if(this._packet.error_msg) return this._disconnect(this._packet.error_msg);
		else if(!payload) return;
		
		if(payload.readUInt8(0) === MESSAGE_NUMBER.SSH_MSG_SERVICE_REQUEST) {
			this._state = state.USER_AUTH;
			payload = payload.slice(1, payload.length);
			if(SSHPacket.readString(payload).string.toString('ascii') === 'ssh-userauth') {
				var user_auth = SSHPacket.createString(new Buffer('ssh-userauth', 'ascii'));
				this._conn.write(this._packet.createBinaryPacket(MESSAGE_NUMBER.SSH_MSG_SERVICE_ACCEPT, SSHPacket.createString(user_auth)));				
			} else {
				throw new Error('unknown service requested: ' + payload);	
			}
		} else 
			throw new Error('unknown request: ' + payload.readUInt8(0));
		break;
	case state.USER_AUTH:
		if(!this._packet.isReadable) return;
		
		this._user.authenticate(this._packet, _.bind(function (err, out) {
			if(this._user.userAuthenticated) {
				this._state = state.CHANNEL;
				this._channel.setUserInfo(this._user.getUserInfo());
			}		
			this._packet.trim();
			this._conn.write(out);
		}, this));
		break;
	case state.CHANNEL:
		if(!this._packet.isReadable) return;		
		
		var packet = this._channel.demultiplex(this._packet, _.bind(function (err, out) {
			this._packet.trim();
			if(out) this._conn.write(out);
		}, this));
		
		if(packet && packet.disconnect_msg) return this._disconnect(this._packet.disconnect_msg);
		else if(packet && packet.error_msg) return this._disconnect(this._packet.error_msg);
		break;
		
	}
};

/** 
 *		RFC 4253 SSH Transport Layer Protocol Section 4.2
 */
TLP.prototype.hello = function (softwareversion, comments) {
	var protocolversion = getProtocolVersion(softwareversion, comments);
	this._kex.setServerProtocolVersion(protocolversion);
	this._conn.write(protocolversion);
};

/** 
 *		RFC 4253 SSH Transport Layer Protocol Section 4.2
 */
TLP.prototype._exchangeProtocolVersion = function (packet) {
	var chs = [];
	while(!packet.eob()) {
		var ch;
		if((ch = packet.readChar()) === '\n') {
			var protover = chs.join('');
			if(!protover.match(/^SSH\-2\.0\-./)) return this._disconnect('not supported version');
			this._kex.setClientProtocolVersion(new Buffer(protover, 'ascii'));
			return;
		} else
			chs.push(ch);
	}
	return this._disconnect('unterminated literal');
};

TLP.prototype._disconnect = function (msg) {
	console.log('disconnect with ' + msg);
	this._conn.destroy();
};

/** 
 *		RFC 4253 SSH Transport Layer Protocol Section 4.2
 */
function getProtocolVersion (softwareversion, comments) {
	return new Buffer('SSH-2.0-' + softwareversion + (comments ? ' ' + comments : '') + '\r\n');
}