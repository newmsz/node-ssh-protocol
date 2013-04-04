var crypto = require('crypto');
var vervose = false, cipher_vervose = false, packet_dump = false;

function SSHPacket() {
	this.length = 0;
	this.isReadable = false;
	this.disconnect_msg = null;
	this.error_msg = null;
	
	this._buf = new Buffer(0);
	this._readoffset = 0;
	
	this._keyAttached = false;
	
	this._recv_bsize = this._send_bsize = 8;
	this._recv_hsize = this._decipherf = this._recv_hmacf = null;
	this._send_hsize = this._send_hmacf = this._cipherf = null;
	
	this._sseq = this._rseq = 0;
}

var MESSAGE_NUMBER = { 
	SSH_MSG_DISCONNECT: 1, 					/* RFC 4253 SSH Transport Layer Protocol Section 12 */
	SSH_MSG_IGNORE: 2, 						/* RFC 4253 SSH Transport Layer Protocol Section 12 */
	SSH_MSG_UNIMPLEMENTED: 3, 				/* RFC 4253 SSH Transport Layer Protocol Section 12 */
	SSH_MSG_DEBUG: 4, 						/* RFC 4253 SSH Transport Layer Protocol Section 12 */
};

exports.SSHPacket = SSHPacket;

/** 
 *		RFC 4253 SSH Transport Layer Protocol Section 6
 */
SSHPacket.prototype.createBinaryPacket = function (msgno, payload) {	
	var payload_length = payload.length + 1,
		padding_length = this._send_bsize;
		
	for(;;padding_length++) {
		if((4+1+payload_length+padding_length) % this._send_bsize === 0) break;
	}
	
	var _msg_no = new Buffer(1),
		_packet_length = new Buffer(4),
		_padding_length = new Buffer(1),
		_padding = crypto.randomBytes(padding_length);
	
	_msg_no.writeUInt8(msgno, 0);
	_padding_length.writeUInt8(padding_length, 0);
	_packet_length.writeUInt32BE(1 + payload_length + padding_length, 0);
	
	payload = Buffer.concat([_packet_length, _padding_length, _msg_no, payload, _padding], 4+1+payload_length+padding_length);
	
	if(this._keyAttached) payload = this._encrypt(payload);	
	//__dump_buffer(payload);
	this._sseq++;
	return payload;
};

/** 
 *		RFC 4253 SSH Transport Layer Protocol Section 6
 */
SSHPacket.prototype.readBinaryPacket = function () {
	if(this._keyAttached) {
		var code = this._decrypt();
		if(code === 0) {
			this.error_msg = 'hmac verification failed'; 
			return null;
		} else if(code === 2) {/* not yet received */
			return null;
		}
	}
	
	var packet_length = this._buf.readUInt32BE(this._readoffset),
		padding_length = this._buf.readUInt8(this._readoffset + 4),
		payload_length = packet_length - padding_length - 2;
	
	if(payload_length + 5 > this.length) return null;
	
	this._rseq++;
	
	switch(this._buf[this._readoffset + 5]) {
	case MESSAGE_NUMBER.SSH_MSG_DISCONNECT: this.disconnect_msg = 'disconnect request'; return null;
	case MESSAGE_NUMBER.SSH_MSG_IGNORE: 
		this._readoffset += packet_length + 4;
		_vervose('-- READED --'); 
		return null;
	case MESSAGE_NUMBER.SSH_MSG_UNIMPLEMENTED:
		this.disconnect_msg = 'receiving client_unimplemented message'; 
		return null;
	}	
	
	var	payload = this._buf.slice(this._readoffset + 5, this._readoffset + 6 + payload_length);
	if((packet_length - 4) % 8 !== 0) {
		this.error_msg = 'padding size failed'; 
		return null;
	} 
	
	_vervose('-- READED --');
	this._readoffset += packet_length + 4;
	this._updateConst();
	return payload;
};

SSHPacket.prototype._encrypt = function (plain) {
	var cipher = this._cipherf(plain),
		seq = new Buffer(4), calculated_mac;
		
	seq.writeUInt32BE(this._sseq, 0);
	calculated_mac = this._send_hmacf(Buffer.concat([seq, plain], plain.length + 4));
	return Buffer.concat([cipher, calculated_mac], cipher.length + calculated_mac.length);
};


SSHPacket.prototype._decrypt = function () {
	_decipher_vervose('	read offset= ' + this._readoffset + ', decipher blocksize= ' + this._recv_bsize + ', hashsize= ' + this._recv_hsize);
	
	var total_read = 0,
		buf_len = this._buf.length,
		_recv_bsize = this._recv_bsize,
		_recv_hsize = this._recv_hsize,
		offset = this._readoffset,
		deciphered = new Buffer(0),
		received_mac;
	
	while(offset + _recv_bsize + _recv_hsize <= buf_len) {
		_decipher_vervose('	reading cipher ' + offset + ' to ' + (offset + _recv_bsize) + '...');
		var cipher = this._buf.slice(offset, (offset + _recv_bsize));
		//_packet_dump('cipher text', cipher);
		deciphered = Buffer.concat([deciphered, this._decipherf(cipher)], deciphered.length + _recv_bsize);
		
		total_read += _recv_bsize;
		offset += _recv_bsize;
		
		var needed = deciphered.readUInt32BE(0) + 4;
		_decipher_vervose('	=> need ' + needed + ' bytes and total read is ' + total_read + ' bytes');
		
		if(needed === total_read) {
			_decipher_vervose('	reading hmac ' + offset + ' to ' + (offset + _recv_hsize) + '...');
			received_mac = this._buf.slice(offset, (offset + _recv_hsize));
			offset += _recv_hsize;
			break;
		}
	}
	
	if(!received_mac) return 2;
	
	var seq = new Buffer(4), calculated_mac;
	seq.writeUInt32BE(this._rseq, 0);
	
	_packet_dump('deciphered text', deciphered);
	_decipher_vervose('	receive packet sequence #' + this._rseq);
	
	calculated_mac = this._recv_hmacf(Buffer.concat([seq, deciphered], deciphered.length + 4));
	
	_packet_dump('received mac', received_mac);
	_packet_dump('calculated mac', calculated_mac);
	
	for(var i=0; i<calculated_mac.length; i++)
		if(calculated_mac[i] !== received_mac[i]) return 0;
	
	var preb = this._buf.slice(0, this._readoffset),
		aftb = this._buf.slice(offset, this._buf.length);
	
	this._buf = Buffer.concat(
				[preb, deciphered, aftb], 
				this._readoffset + total_read + this._buf.length - offset); 
	_vervose('-- DECRYPTED --');
	this._updateConst();
	return 1;
};

SSHPacket.prototype.attachKeyFunctions = function (
		recv_hsize, recv_bsize, recv_hmacf, decipherf, 
		send_hsize, send_bsize, send_hmacf, cipherf) {
	this._recv_hsize = recv_hsize;
	this._recv_bsize = recv_bsize;
	this._recv_hmacf = recv_hmacf;
	this._decipherf = decipherf;
	
	this._send_hsize = send_hsize;
	this._send_bsize = send_bsize;
	this._send_hmacf = send_hmacf;
	this._cipherf = cipherf;
	
	this._keyAttached = true;
};

SSHPacket.prototype.eob = function () {
	return this._readoffset === this._buf.length;
};

SSHPacket.prototype.readUInt8 = function () {
	return this._buf.readUInt8(this._readoffset++);
};

SSHPacket.prototype.readChar = function () {
	return String.fromCharCode(this.readUInt8());
};

SSHPacket.prototype.append = function (buf) {
	_vervose('-- ' + buf.length + ' BYTES APPENDED --');
	this._buf = Buffer.concat([this._buf, buf], this._buf.length + buf.length);
	this._updateConst();
};

SSHPacket.prototype._updateConst = function () {
	this.length = this._buf.length - this._readoffset;
	
	if(this._buf.length === 0) {
		this._readoffset = 0;
		this.length = 0;
		this.isReadable = false;
	} else if(this.eob()) {
		this.isReadable = false;
	} else if(this.length > 5) {
		this.isReadable = true;
	} else 
		this.isReadable = false;
	_vervose('buflen: ' + this._buf.length + ', offset: ' + this._readoffset + ', length: ' + this.length + ', ' + this.isReadable); 
};

SSHPacket.prototype.trim = function (buf) {
	_vervose('-- TRIMMED --');
	this._buf = this._buf.slice(this._readoffset, this._buf.length);
	this._readoffset = 0;
	this.length = this._buf.length;
	this._updateConst();
};

function _vervose (msg) {
	if(vervose) console.error('BUFFER: ' + msg);
}

function _decipher_vervose (msg) {
	if(cipher_vervose) console.error('BUFFER: DECIPHER: ' + msg);
}

function _packet_dump (name, buf) {
	if(packet_dump) {
		console.error('BUFFER: -- ' + name + ' DUMP BEGIN -- ');
		__dump_buffer(buf);
		console.error('BUFFER: --' + name + ' DUMP END --');
	}
}


/** 
 *		RFC 4251 SSH Protocol Architecture Section 5
 */
var createMPInt = exports.createMPInt = function (buf) {
	if(typeof buf === 'number') {
		var n = buf;
		buf = new Buffer(4);
		buf.writeUInt32BE(n, 0);
	}
	var len = new Buffer(4),
		value = buf;
	len.writeUInt32BE(buf.length, 0);
	return Buffer.concat([len, value], 4 + buf.length);
}

var createMPUInt = exports.createMPUInt = function (buf) {
	if(typeof buf === 'number') {
		var n = buf;
		buf = new Buffer(4);
		buf.writeUInt32BE(n, 0);
	}
	if(buf.readUInt8(0) & 0x80) buf = Buffer.concat([new Buffer('00', 'hex'), buf], buf + 1);
	var len = new Buffer(4);
	len.writeUInt32BE(buf.length, 0);
	return Buffer.concat([len, buf], 4 + buf);
}

/** 
 *		RFC 4251 SSH Protocol Architecture Section 5
 */
var readMPInt = exports.readMPInt = function (buf, offset) {
	offset = offset || 0;
	var len = buf.readUInt32BE(offset);
	return { mpint: buf.slice(offset + 4, offset + 4 + len), offset: offset + len + 4 };
}

/** 
 *		RFC 4251 SSH Protocol Architecture Section 5
 */
var createString = exports.createString = function (str) {
	var len = new Buffer(4),
		value = Buffer.isBuffer(str) ? str : new Buffer(str);
	len.writeUInt32BE(str.length, 0);
	return Buffer.concat([len, value], 4 + str.length);
}

/** 
 *		RFC 4251 SSH Protocol Architecture Section 5
 */
var readString = exports.readString = function (buf, offset) {
	offset = offset || 0;
	var len = buf.readUInt32BE(offset);
	return { string: buf.slice(offset + 4, offset + 4 + len), offset: offset + len + 4 };
}

/** 
 *		RFC 4251 SSH Protocol Architecture Section 5
 */
var createNameList = exports.createNameList = function (arr) {
	if(!Array.isArray(arr)) throw new Error('parameter is not an array');
	arr = arr.join(',');
	var len = new Buffer(4),
		value = new Buffer(arr);
	len.writeUInt32BE(arr.length, 0);
	return Buffer.concat([len, value], 4 + arr.length);
}

/** 
 *		RFC 4251 SSH Protocol Architecture Section 5
 */
var readNameList = exports.readNameList = function (buf, offset) {
	offset = offset || 0;
	var len = buf.readUInt32BE(offset);
	return { namelist: buf.slice(offset + 4, offset + 4 + len).toString('ascii').split(','), offset: offset + len + 4 };
}

var __dump_buffer = exports.__dump_buffer = function (buf) {
	var i=0;
	if(buf.length >= 16) 
		for(i=16; i<=buf.length; i+=16) 
			console.error((i-16) + ':' + i, buf.slice(i-16, i));
	if(i-16< buf.length)
		console.error((i-16) + ':' + buf.length, buf.slice(i-16, buf.length));
}