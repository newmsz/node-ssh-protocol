var	_ = require('underscore'),
	SSHPacket = require('./ssh-packet');
     
var MESSAGE_NUMBER = { 
	SSH_MSG_GLOBAL_REQUEST: 80, 			/* RFC 4254 SSH Connection Protocol Section 9 */
	SSH_MSG_REQUEST_SUCCESS: 81,			/* RFC 4254 SSH Connection Protocol Section 9 */
	SSH_MSG_REQUEST_FAILURE: 82,			/* RFC 4254 SSH Connection Protocol Section 9 */
	SSH_MSG_CHANNEL_OPEN: 90,				/* RFC 4254 SSH Connection Protocol Section 9 */
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION: 91,	/* RFC 4254 SSH Connection Protocol Section 9 */
	SSH_MSG_CHANNEL_OPEN_FAILURE: 92,		/* RFC 4254 SSH Connection Protocol Section 9 */
	SSH_MSG_CHANNEL_WINDOW_ADJUST: 93,		/* RFC 4254 SSH Connection Protocol Section 9 */
	SSH_MSG_CHANNEL_DATA: 94,				/* RFC 4254 SSH Connection Protocol Section 9 */
	SSH_MSG_CHANNEL_EXTENDED_DATA: 95,		/* RFC 4254 SSH Connection Protocol Section 9 */
	SSH_MSG_CHANNEL_EOF: 96,				/* RFC 4254 SSH Connection Protocol Section 9 */
	SSH_MSG_CHANNEL_CLOSE: 97,				/* RFC 4254 SSH Connection Protocol Section 9 */
	SSH_MSG_CHANNEL_REQUEST: 98,			/* RFC 4254 SSH Connection Protocol Section 9 */
	SSH_MSG_CHANNEL_SUCCESS: 99,			/* RFC 4254 SSH Connection Protocol Section 9 */
	SSH_MSG_CHANNEL_FAILURE: 100			/* RFC 4254 SSH Connection Protocol Section 9 */
};

var REASON_CODE = {
	SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: 1,	/* RFC 4254 SSH Connection Protocol Section 5.1 */
	SSH_OPEN_CONNECT_FAILED: 2,					/* RFC 4254 SSH Connection Protocol Section 5.1 */
	SSH_OPEN_UNKNOWN_CHANNEL_TYPE: 3,			/* RFC 4254 SSH Connection Protocol Section 5.1 */
	SSH_OPEN_RESOURCE_SHORTAGE: 4				/* RFC 4254 SSH Connection Protocol Section 5.1 */
};
  
var ESCAPE_SEQUENCE = { 
	'clear': '\033[2J' 
};

var SUPPORTED_CHANNEL_TYPE = ['session', /*'x11', 'forwarded-tcpip', 'direct-tcpip'*/];
var SUPPORTED_CHANNEL_REQUEST_TYPE = ['pty-req', /*'x11-req'*/, 'env', 'shell', /*'exec', 'subsystem',*/ 'window-change', /*'xon-xoff', 'signal', 'exit-status', 'exit-signal'*/];

function SSHChannel() {
	this._channels = {};
	this._channel_cnt = 0;
	
	this._ondata = null;
	this._userinfo = null;
}

exports.SSHChannel = SSHChannel;

SSHChannel.prototype.onData = function (cb) { this._ondata = cb; };
SSHChannel.prototype.setUserInfo = function (ui) {
	this._userinfo = ui;
};

SSHChannel.prototype.demultiplex = function (packet, cb) {
	var payload = packet.readBinaryPacket();
	
	if(packet.disconnect_msg) return packet;
	else if(packet.error_msg) return packet;
	
	var msgno = payload.readUInt8(0),
		payload = payload.slice(1, payload.length);
	
	switch(msgno) {
	case MESSAGE_NUMBER.SSH_MSG_CHANNEL_OPEN:
		this._openChannel(payload, _.bind(function (err, o_msgno, o_payload) {
			return cb(err, packet.createBinaryPacket(o_msgno, o_payload));
		}, this));
		break;
	case MESSAGE_NUMBER.SSH_MSG_CHANNEL_REQUEST:		
		this._forwardRequestToChannel(payload, _.bind(function (err, o_msgno, o_payload) {
			return cb(err, packet.createBinaryPacket(o_msgno, o_payload));
		}, this));
		break;
	case MESSAGE_NUMBER.SSH_MSG_CHANNEL_DATA:
		this._forwardDataToChannel(payload, _.bind(function (err, o_msgno, o_payload) {
			return cb(err, packet.createBinaryPacket(o_msgno, o_payload));
		}, this));
		break;
	default:
		console.log(msgno);
	}
	
	packet.trim();
	if(packet.isReadable) this.demultiplex(packet, cb);
};

SSHChannel.prototype._openChannel = function (payload, cb) {
	var channel_type = SSHPacket.readString(payload);
	payload = payload.slice(channel_type.offset, payload.length);
	channel_type = channel_type.string.toString('ascii');
	
	var sender_channel = payload.readUInt32BE(0),
		window_size = payload.readUInt32BE(4),
		max_packet_size = payload.readUInt32BE(8);
	payload = payload.slice(12, payload.length);
		
	var recipient_channel = new Buffer(4);
	recipient_channel.writeUInt32BE(sender_channel, 0);
	
	switch(channel_type) {
	case 'session':
		var channel_no = this._openSessionChannel(sender_channel, window_size, max_packet_size), 
			channel = this._getChannel(channel_no),
			channel_message = channel.getConfirmMessage(),
			sender_channel = new Buffer(4);
			
		sender_channel.writeUInt32BE(channel_no, 0);
		return cb(null, 
				MESSAGE_NUMBER.SSH_MSG_CHANNEL_OPEN_CONFIRMATION, 
				Buffer.concat([recipient_channel, sender_channel, channel_message], 8 + channel_message.length)
		);		
		
		break;
	default:
		var reason_code = new Buffer(4),
			description = SSHPacket.createString(new Buffer('not supported channel type: ' + channel_type, 'ascii')),
			language = SSHPacket.createString(new Buffer('en', 'ascii'));
		reason_code.writeUInt32BE(REASON_CODE.SSH_OPEN_UNKNOWN_CHANNEL_TYPE, 0);
		return cb(null, MESSAGE_NUMBER.SSH_MSG_CHANNEL_OPEN_FAILURE, Buffer.concat([recipient_channel, reason_code, description, language], 8 + description.length + language.length));
	}
};

SSHChannel.prototype._forwardRequestToChannel = function (payload, cb) {
	var channel_no = payload.readUInt32BE(0),
		channel = this._getChannel(channel_no);
		
	if(!channel) {
		channel_no = new Buffer(4);
		channel_no.writeUInt32BE(payload.readUInt32BE(0), 0);
		return cb(null, MESSAGE_NUMBER.SSH_MSG_CHANNEL_FAILURE, channel_no);
	}
		
	payload = payload.slice(4, payload.length);
	
	var req = SSHPacket.readString(payload);
	payload = payload.slice(req.offset, payload.length);
	req = req.string.toString('ascii');
	var want_reply = payload.readUInt8(0);
	payload = payload.slice(1, payload.length);
	
	channel.processRequest(req, want_reply, payload, cb);
};

SSHChannel.prototype._forwardDataToChannel = function (payload, cb) {
	var channel_no = payload.readUInt32BE(0),
		channel = this._getChannel(channel_no);
		
	if(!channel) {
		channel_no = new Buffer(4);
		channel_no.writeUInt32BE(payload.readUInt32BE(0), 0);
		return cb(null, MESSAGE_NUMBER.SSH_MSG_CHANNEL_FAILURE, channel_no);
	}
	
	var data = SSHPacket.readString(payload.slice(4, payload.length)).string;
	var request = {
		channel: {
			type: channel.type,
			window_size: channel.window_size,
			environmental_variables: channel._env,
			isShell: channel._shell
		},
		user: this._userinfo.userinfo,
		data: data,
	};
	
	if(channel._terminal) { 
		request.terminal = {
			environment: channel._terminal.environment,
			columns: channel._terminal.columns,
			rows: channel._terminal.rows,
			width: channel._terminal.pixel_width,
			height: channel._terminal.pixel_height,
			mode: channel._terminal.mode
		};
	}
	
	this._ondata(request, buildResponseObject(channel.client_channel, cb));
};

function buildResponseObject(client_channel, cb) {
	var recipient_channel = new Buffer(4),
		code = new Buffer(4);
	recipient_channel.writeUInt32BE(client_channel, 0);
	code.writeUInt32BE(1, 0);
	
	var response = {
		stdout: function (data) {
			if(!Buffer.isBuffer(data)) data = new Buffer('data');
			data = SSHPacket.createString(data);
			return cb(null, MESSAGE_NUMBER.SSH_MSG_CHANNEL_DATA, Buffer.concat([recipient_channel, data], data.length + 4));			 
		}, 
		stderr: function (data) {
			if(!Buffer.isBuffer(data)) data = new Buffer('data');
			data = SSHPacket.createString(data);
			return cb(null, MESSAGE_NUMBER.SSH_MSG_CHANNEL_EXTENDED_DATA, Buffer.concat([recipient_channel, code, data], data.length + 8)); 
		}
	};
	
	for(var i=0; i<__ESCAPE_SEQ_KEY.length; i++) {
		var seq = ESCAPE_SEQUENCE[__ESCAPE_SEQ_KEY[i]];
		response[__ESCAPE_SEQ_KEY[i]] = function () {
			return cb(null, MESSAGE_NUMBER.SSH_MSG_CHANNEL_DATA, Buffer.concat([recipient_channel, seq], seq.length + 4));
		};
	}

	return response;
}

function Channel(type, user, client_channel, window_size, max_packet_size) {
	this.type = type;
	this.user = user;
	this.client_channel = client_channel;
	this.window_size = window_size;
	this.max_packet_size = max_packet_size;
	
	this._env = {};
	this._shell = false;		/* activated by "shell" */
	this._terminal = null;	/* activated by "pty-req" */
}

Channel.prototype.processRequest = function (req, want_reply, payload, cb) {
	switch(req) {
	case 'pty-req':
		var term_env = SSHPacket.readString(payload);
		payload = payload.slice(term_env.offset, payload.length);
		term_env = term_env.string.toString('ascii');
		
		var terminal_char_width = payload.readUInt32BE(0),
			terminal_rows = payload.readUInt32BE(4),
			terminal_width = payload.readUInt32BE(8),
			terminal_height = payload.readUInt32BE(12);
		
		payload = payload.slice(16, payload.length);
		var encoded_mode = SSHPacket.readString(payload).string;
		
		this._pseudoTerminal(term_env, terminal_char_width, terminal_rows, terminal_width, terminal_height, encoded_mode);
		
		var client_channel = new Buffer(4),
			clear = ESCAPE_SEQUENCE.clear;
		client_channel.writeUInt32BE(this.client_channel, 0);
		cb(null, MESSAGE_NUMBER.SSH_MSG_CHANNEL_DATA, Buffer.concat([client_channel, clear], clear.length + 4));
		break;
	case 'shell':
		this._enableShell();
		break;
	case 'window-change':
		var terminal_char_width = payload.readUInt32BE(0),
			terminal_rows = payload.readUInt32BE(4),
			terminal_width = payload.readUInt32BE(8),
			terminal_height = payload.readUInt32BE(12);
		this._windowChange(terminal_char_width, terminal_rows, terminal_width, terminal_height);
		break;
	case 'env':
		var env = SSHPacket.readString(payload);
		payload = payload.slice(env.offset, payload.length);
		env = env.string;
		var val = SSHPacket.readString(payload);
		payload = payload.slice(val.offset, payload.length);
		val = val.string;
		this._setEnv(env.toString(), val.toString());
		break;
	/*case 'x11-req':
	case 'exec':
	case 'subsystem':
	case 'xon-xoff':
	case 'signal':
	case 'exit-status':
	case 'exit-signal':*/
	default:
		throw new Error('unknown request: ' + req);
		console.log(req, want_reply, payload);
		var channel_no = new Buffer(4);
		channel_no.writeUInt32BE(this.client_channel, 0);
		return cb(null, MESSAGE_NUMBER.SSH_MSG_CHANNEL_FAILURE, channel_no);
	}

	if(want_reply === 1) {
		var channel_no = new Buffer(4);
		channel_no.writeUInt32BE(this.client_channel, 0);
		return cb(null, MESSAGE_NUMBER.SSH_MSG_CHANNEL_SUCCESS, channel_no);
	}
};

Channel.prototype._setEnv = function (name, value) {
	this._env[name] = value;
};

Channel.prototype._enableShell = function () {
	this._shell = true;
};

Channel.prototype._windowChange = function (terminal_char_width, terminal_rows, terminal_width, terminal_height) {
	this._terminal.columns = terminal_char_width;
	this._terminal.rows = terminal_rows;
	this._terminal.pixel_width = terminal_width;
	this._terminal.pixel_height = terminal_height;
};

Channel.prototype._pseudoTerminal = function (terminal_environment, char_width, rows, width_pixel, height_pixel, encoded_modes) {
	this._terminal = {
		environment: terminal_environment,
		columns: char_width,
		rows: rows,
		pixel_width: width_pixel,
		pixel_height: height_pixel,
		mode: null,
	};
};

Channel.prototype.getConfirmMessage = function () {
	var initial_window_size = new Buffer(4),
		maximum_packet_size = new Buffer(4),
		output;
	
	initial_window_size.writeUInt32BE(this.window_size, 0);
	maximum_packet_size.writeUInt32BE(this.max_packet_size, 0);
	
	switch(this.type) {
	case 'session':
		output = Buffer.concat([initial_window_size, maximum_packet_size], 8);
		break;
	}
	
	return output;
};

SSHChannel.prototype._getChannel = function(cn) {
	return this._channels[cn];
};

SSHChannel.prototype._openSessionChannel = function(sender_channel, window_size, max_packet_size) {
	var channel = new Channel('session', this._userinfo, sender_channel, window_size, max_packet_size);
	this._channels[this._channel_cnt] = channel;
	return this._channel_cnt++;
};

var __ESCAPE_SEQ_KEY = _.keys(ESCAPE_SEQUENCE);
for(var i=0; i<__ESCAPE_SEQ_KEY.length; i++) {
	ESCAPE_SEQUENCE[__ESCAPE_SEQ_KEY[i]] = SSHPacket.createString(new Buffer(ESCAPE_SEQUENCE[__ESCAPE_SEQ_KEY[i]]));
}