var crypto = require('crypto'),
	_ = require('underscore');
var SSHPacket = require('./ssh-packet');

var state = {
	ALGORITHM_NEGOTIATION: 'ALGORITHM_NEGOTIATION',
	KEY_EXCHANGE_REQUEST: 'KEY_EXCHANGE_REQUEST',
	KEY_EXCHANGE_INIT: 'KEY_EXCHANGE_INIT',
	KEY_EXCHANGE_FINISH: 'KEY_EXCHANGE_FINISH',
	ESTABLISHED: 'ESTABLISHED'
};

var SUPPORTED_ALGORITHMS = { 
	KEX_ALGORITHMS: ['diffie-hellman-group-exchange-sha256', /*'diffie-hellman-group-exchange-sha1', 'diffie-hellman-group14-sha1', 'diffie-hellman-group1-sha1'*/], 
	SERVER_HOST_KEY_ALGORITHMS: [/*'ssh-rsa', 'ssh-dss'*/], 
	ENCRPYTION_ALGORITHMS_CLIENT_TO_SERVER: ['aes256-cbc', 'aes128-cbc'], 
	ENCRPYTION_ALGORITHMS_SERVER_TO_CLIENT: ['aes256-cbc', 'aes128-cbc'], 
	MAC_ALGORITHMS_CLIENT_TO_SERVER: ['hmac-sha1', 'hmac-md5'],
	MAC_ALGORITHMS_SERVER_TO_CLIENT: ['hmac-sha1', 'hmac-md5'], 
	COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER: ['none'], 
	COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT: ['none'] 
};

var MESSAGE_NUMBER = { 
	SSH_MSG_KEXINIT: 20, 					/* RFC 4253 SSH Transport Layer Protocol Section 12 */
	SSH_MSG_NEWKEYS: 21,					/* RFC 4253 SSH Transport Layer Protocol Section 12 */
	SSH_MSG_KEX_DH_GEX_REQUEST_OLD: 30,		/* RFC 4419 SSH DH Group Exchange Section 5 */
	SSH_MSG_KEX_DH_GEX_REQUEST: 34,			/* RFC 4419 SSH DH Group Exchange Section 5 */
	SSH_MSG_KEX_DH_GEX_GROUP: 31,			/* RFC 4419 SSH DH Group Exchange Section 5 */
	SSH_MSG_KEX_DH_GEX_INIT: 32,			/* RFC 4419 SSH DH Group Exchange Section 5 */
	SSH_MSG_KEX_DH_GEX_REPLY: 33			/* RFC 4419 SSH DH Group Exchange Section 5 */
};

var SERVER_HOST_KEY = { 'ssh-rsa': null, 'ssh-dss': null };

function SSHKex() {
	this.keyExchanged = false;

	this._state = state.ALGORITHM_NEGOTIATION;
	
	this._kex_algorithm = null;
	this._host_key_algorithm = null;
	this._recv_encryption_algorithm = null;
	this._send_encryption_algorithm = null;
	this._recv_mac_algorithm = null;
	this._send_mac_algorithm = null;
	this._recv_compression_algorithm = null;
	this._send_compression_algorithm = null;
	this._recv_language = null;
	this._send_language = null;

	this._keys = null;
	
	this._exchange_hash_mode = 'extp';
	this._exchange_hash = {V_C: null, V_S: null, I_C: null, I_S: null, K_S: null, min: null, n: null, max: null, p: null, g: null, e: null, f: null, K: null };
}

exports.SSHKex = SSHKex;
exports.enableSSHRSA = enableSSHRSA;

SSHKex.prototype.exchangeKeys = function (packet, cb) {	
	var payload = packet.readBinaryPacket();
	
	 if(!payload) return;	
	if(packet.disconnect_msg) return cb(null, packet.disconnect_msg);
	
	var msgno = payload.readUInt8(0),
		payload = payload.slice(1, payload.length),
		output;
	
	switch(this._state) {
	case state.ALGORITHM_NEGOTIATION:
		output = packet.createBinaryPacket(MESSAGE_NUMBER.SSH_MSG_KEXINIT, this._negotiateAlgorithms(msgno, payload))
		this._state = state.KEY_EXCHANGE_REQUEST;	
		break;
	case state.KEY_EXCHANGE_REQUEST:
		output = packet.createBinaryPacket(MESSAGE_NUMBER.SSH_MSG_KEX_DH_GEX_GROUP, this._exchangeDHGroup(msgno, payload))
		this._state = state.KEY_EXCHANGE_INIT;
		break;
	case state.KEY_EXCHANGE_INIT:
		output = packet.createBinaryPacket(MESSAGE_NUMBER.SSH_MSG_KEX_DH_GEX_REPLY, this._DHGroupExchangeInit(msgno, payload))
		this._state = state.KEY_EXCHANGE_FINISH; 
		break;
	case state.KEY_EXCHANGE_FINISH:
		this._deriveKeys();
		output = packet.createBinaryPacket(MESSAGE_NUMBER.SSH_MSG_NEWKEYS, new Buffer(0))
		this.keyExchanged = true;
		break;
	default:
		throw new Error('unknown state in packet: ' + this._state);
	}
	
	return cb(null, output);
};

function enableSSHRSA(publickey, privatekey) {
	publickey = publickey.split(' ');
	if(publickey.length < 2 || publickey[0] !== 'ssh-rsa') throw new Erorr('public key is not in PEM format');

	if(!SERVER_HOST_KEY['ssh-rsa']) SERVER_HOST_KEY['ssh-rsa'] = {};
	SERVER_HOST_KEY['ssh-rsa'].publickey = verifySSHRSAPublicKey(new Buffer(publickey[1], 'base64'));
	SERVER_HOST_KEY['ssh-rsa'].privatekey = privatekey;
	
	SUPPORTED_ALGORITHMS.SERVER_HOST_KEY_ALGORITHMS.push('ssh-rsa');
}

SSHKex.prototype.setServerProtocolVersion = function (V_S) {
	this._exchange_hash_update('V_S', V_S);
};

SSHKex.prototype.setClientProtocolVersion = function (V_C) {
	this._exchange_hash_update('V_C', V_C);
};

/** 
 *		RFC 4253 SSH Transport Layer Protocol Section 7.1
 */
SSHKex.prototype._negotiateAlgorithms = function (msgno, payload) { 
	if(msgno !== MESSAGE_NUMBER.SSH_MSG_KEXINIT) return this._error(new Error('key is not exchanged yet'));
	this._exchange_hash_update('I_C', payload);
	
	var offset = 16;
	while(offset + 1 < payload.length) {
		var namelist = SSHPacket.readNameList(payload, offset);
		offset = namelist.offset;
		namelist = namelist.namelist;
		
		if(this._kex_algorithm === null) {
			var itc = _.intersection(namelist, SUPPORTED_ALGORITHMS.KEX_ALGORITHMS);
			if(itc.length > 0) this._kex_algorithm = itc[0];
			else return this._error(new Error('not supported key exchange algorithm: ' + namelist.join(',')));
		} else if(this._host_key_algorithm === null) {
			var itc = _.intersection(namelist, SUPPORTED_ALGORITHMS.SERVER_HOST_KEY_ALGORITHMS);
			if(itc.length > 0) this._host_key_algorithm = itc[0];
			else return this._error(new Error('not supported server host key algorithm: ' + namelist.join(',')));
		} else if(this._recv_encryption_algorithm === null) {
			var itc = _.intersection(namelist, SUPPORTED_ALGORITHMS.ENCRPYTION_ALGORITHMS_CLIENT_TO_SERVER);
			if(itc.length > 0) this._recv_encryption_algorithm = itc[0];
			else return this._error(new Error('not supported encrpytion algorithms client to server: ' + namelist.join(',')));
		} else if(this._send_encryption_algorithm === null) {
			var itc = _.intersection(namelist, SUPPORTED_ALGORITHMS.ENCRPYTION_ALGORITHMS_SERVER_TO_CLIENT);
			if(itc.length > 0) this._send_encryption_algorithm = itc[0];
			else return this._error(new Error('not supported encrpytion algorithms server to client: ' + namelist.join(',')));
		} else if(this._recv_mac_algorithm === null) {
			var itc = _.intersection(namelist, SUPPORTED_ALGORITHMS.MAC_ALGORITHMS_CLIENT_TO_SERVER);
			if(itc.length > 0) this._recv_mac_algorithm = itc[0];
			else return this._error(new Error('not supported mac algorithms client to server: ' + namelist.join(',')));
		} else if(this._send_mac_algorithm === null) {
			var itc = _.intersection(namelist, SUPPORTED_ALGORITHMS.MAC_ALGORITHMS_SERVER_TO_CLIENT);
			if(itc.length > 0) this._send_mac_algorithm = itc[0];
			else return this._error(new Error('not supported mac algorithms server to client: ' + namelist.join(',')));
		} else if(this._recv_compression_algorithm === null) {
			var itc = _.intersection(namelist, SUPPORTED_ALGORITHMS.COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER);
			if(itc.length > 0) this._recv_compression_algorithm = itc[0];
			else return this._error(new Error('not supported compression algorithms client to server: ' + namelist.join(',')));
		} else if(this._send_compression_algorithm === null) {
			var itc = _.intersection(namelist, SUPPORTED_ALGORITHMS.COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT);
			if(itc.length > 0) this._send_compression_algorithm = itc[0];
			else return this._error(new Error('not supported compression algorithms server to client: ' + namelist.join(',')));
		} else if(this._recv_language === null) {
			this._recv_language = namelist.join(',');
		} else if(this._send_language === null) {
			this._send_language = namelist.join(',');
		} else if(payload.length - offset !== 1) {
			return this._error(new Error('unrecognizable first_kex_packet_follows and uint32'));
		} 
	}

	var cookie = crypto.randomBytes(16),
		
		kex_algorithms = SSHPacket.createNameList([this._kex_algorithm]),
		server_host_key_algorithms = SSHPacket.createNameList([this._host_key_algorithm]),
		encryption_algorithms_client_to_server = SSHPacket.createNameList([this._recv_encryption_algorithm]),
		encryption_algorithms_server_to_client = SSHPacket.createNameList([this._send_encryption_algorithm]),
		mac_algorithms_client_to_server = SSHPacket.createNameList([this._recv_mac_algorithm]),
		mac_algorithms_server_to_client = SSHPacket.createNameList([this._send_mac_algorithm]),
		compression_algorithms_client_to_server = SSHPacket.createNameList([this._recv_compression_algorithm]),
		compression_algorithms_server_to_client = SSHPacket.createNameList([this._send_compression_algorithm]),
		languages_client_to_server = SSHPacket.createNameList([]), 
		languages_server_to_client = SSHPacket.createNameList([]),
		
		boolean = new Buffer(1),
		uint32 = new Buffer(4);
	
	boolean.writeUInt8(0, 0);	
	uint32.writeUInt32BE(0, 0);
	
	var I_S = Buffer.concat([
			cookie, 
			kex_algorithms,
			server_host_key_algorithms,
			encryption_algorithms_client_to_server,
			encryption_algorithms_server_to_client,
			mac_algorithms_client_to_server,
			mac_algorithms_server_to_client,
			compression_algorithms_client_to_server,
			compression_algorithms_server_to_client,
			languages_client_to_server, 
			languages_server_to_client, 
			boolean, 
			uint32], 
			16 + 
			kex_algorithms.length +
			server_host_key_algorithms.length + 
			encryption_algorithms_client_to_server.length +
			encryption_algorithms_server_to_client.length +
			mac_algorithms_client_to_server.length +
			mac_algorithms_server_to_client.length +
			compression_algorithms_client_to_server.length +
			compression_algorithms_server_to_client.length +
			languages_client_to_server.length +
			languages_server_to_client.length +
			5
		);
		
	this._exchange_hash_update('I_S', I_S);	
	return I_S;
};

/** 
 *		RFC 4419 SSH DH Group Exchange Section 3
 */
SSHKex.prototype._exchangeDHGroup = function (msgno, payload) {
	var acceptable_group_size = 4096;
	switch(msgno) {
	case MESSAGE_NUMBER.SSH_MSG_KEX_DH_GEX_REQUEST:
		if(payload.length !== 12) this._error(new Error('invalid message format dh gex request'));
		var min = payload.slice(0, 4).readUInt32BE(0),
			n = payload.slice(4, 8).readUInt32BE(0),
			max = payload.slice(8, 12).readUInt32BE(0);
			
		this._exchange_hash_update('min', min);
		this._exchange_hash_update('n', n);
		this._exchange_hash_update('max', max);
		
		if(acceptable_group_size < min || acceptable_group_size > max)
			acceptable_group_size = n;	
		break;
	case MESSAGE_NUMBER.SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
		if(payload.length !== 4) this._error(new Error('invalid message format dh gex request'));
		var n = acceptable_group_size = payload.readUInt32BE(0);
		
		this._exchange_hash_update('min', 1024);
		this._exchange_hash_update('n', n);
		this._exchange_hash_update('max', 8192);
		
		break;
	default:
		return this._error(new Error('unknown message number'));
	}
	
	switch(acceptable_group_size) {
	case 1024: this._dh_group = 'modp2'; break;
	case 1536: this._dh_group = 'modp5'; break;
	case 2048: this._dh_group = 'modp14'; break;
	case 3072: this._dh_group = 'modp15'; break;
	case 4096: this._dh_group = 'modp16'; break;
	case 6144: this._dh_group = 'modp17'; break;
	case 8192: this._dh_group = 'modp18'; break;
	default: return this._error(new Error('unacceptable group size: ' + acceptable_group_size)); 
	}
	
	var dh = this._dhf(),
		prime = new Buffer(dh.getPrime(), 'binary'),
		generator = new Buffer(dh.getGenerator(), 'binary');
	
	prime = SSHPacket.createMPUInt(prime);
	generator = SSHPacket.createMPInt(generator);
	
	this._exchange_hash_update('p', prime);
	this._exchange_hash_update('g', generator);
	
	return Buffer.concat([prime, generator], prime.length + generator.length);
};

/** 
 *		RFC 4419 SSH DH Group Exchange Section 3
 */
SSHKex.prototype._DHGroupExchangeInit = function (msgno, payload) {
	if(msgno !== MESSAGE_NUMBER.SSH_MSG_KEX_DH_GEX_INIT) return this._error(new Error('unknown message number: ' + msgno));
	
	this._exchange_hash_update('e', payload);
	var mpint = SSHPacket.readMPInt(payload).mpint,	
		dh = this._dhf();
		host_key = SERVER_HOST_KEY[this._host_key_algorithm].publickey.key;
	
	dh.generateKeys();
	
	this._exchange_hash.K_S = SERVER_HOST_KEY[this._host_key_algorithm].publickey.key;
	
	var public_key = new Buffer(dh.getPublicKey(), 'binary'),
		private_key = new Buffer(dh.getPrivateKey(), 'binary'),
		shared_key = new Buffer(dh.computeSecret(mpint), 'binary');
		
	this._dh_server_shared_key = shared_key;
	
	public_key = SSHPacket.createMPUInt(public_key);
	shared_key = SSHPacket.createMPUInt(shared_key);
	
	this._exchange_hash_update('f', public_key);
	this._exchange_hash_update('K', shared_key);
	
	var signer = this._signf(),
		signature = signer.update(this._exchange_hash_finalize()),
		type = SSHPacket.createString(this._host_key_algorithm); /* RFC 4253 SSH Transport Layer Protocol Section 6.6 */

	signature = SSHPacket.createString(new Buffer(signer.sign(SERVER_HOST_KEY[this._host_key_algorithm].privatekey), 'binary'));
	signature = SSHPacket.createString(Buffer.concat([type, signature], type.length + signature.length));
	
	return Buffer.concat([host_key, public_key, signature], host_key.length + public_key.length + signature.length);	
};

/** 
 *		RFC 4253 SSH Transport Layer Protocol Section 7.2
 */
SSHKex.prototype._deriveKeys = function () {
	var K = SSHPacket.createMPUInt(this._dh_server_shared_key),
		H = this._exchange_hash,
		session_id = this._session_identifier,
		deriveKey = function (K, H, x, session_id, len) {
			var buf = Buffer.concat([K, H, new Buffer(x), session_id], K.length + H.length + session_id.length + 1),
			hash = this._hash(buf);
			if(len === hash.length) return hash;
			else if(len < hash.length) return hash.slice(0, len);
			throw new Error('hash length is less than the required key length');
		};
		
	this._keys = {
		IV_ctos: deriveKey.call(this, K, H, 'A', session_id, this._recv_cblocksize()),
		IV_stoc: deriveKey.call(this, K, H, 'B', session_id, this._send_cblocksize()),
		EK_ctos: deriveKey.call(this, K, H, 'C', session_id, this._recv_cblocksize()),
		EK_stoc: deriveKey.call(this, K, H, 'D', session_id, this._send_cblocksize()),
		IK_ctos: deriveKey.call(this, K, H, 'E', session_id, this._recv_mblocksize()),
		IK_stoc: deriveKey.call(this, K, H, 'F', session_id, this._send_mblocksize())
	};
};

SSHKex.prototype._exchange_hash_update = function (name, val) {
	switch(name) {
	case 'V_C':
	case 'V_S':
		for(var i=val.length - 1; i>=0; i--) {
			if(val[i] !== 0x0a && val[i] !== 0x0d) {
				val = val.slice(0, i + 1);
				break;
			}
		}
		val = SSHPacket.createString(val);
		break;
	case 'I_C':
	case 'I_S':
		val = Buffer.concat([new Buffer(1), val], val + 1);
		val.writeUInt8(MESSAGE_NUMBER.SSH_MSG_KEXINIT, 0);
		val = SSHPacket.createString(val);
		break;
	case 'min':
	case 'n':
	case 'max':
		var _buf = new Buffer(4);
		_buf.writeUInt32BE(val, 0);
		val = _buf;
		break;
	case 'p':
	case 'g':
	case 'e':
	case 'f':
	case 'K':
		break;
	default: throw new Error('unknown exchange hash name: ' + name);
	}
	
	this._exchange_hash[name] = val;
};

SSHKex.prototype._exchange_hash_finalize = function () {
	var comc = [], ln = 0, _exchange_hash = this._exchange_hash,
		p = { oldp: ['V_C', 'V_S', 'I_C', 'I_S', 'K_S', 'e', 'f', 'K'],
			  extp: ['V_C', 'V_S', 'I_C', 'I_S', 'K_S', 'min', 'n', 'max', 'p', 'g', 'e', 'f', 'K'] };
	p[this._exchange_hash_mode].forEach(function (cv) { 
		if(!_exchange_hash[cv]) throw new Error(cv + ' is not set');
		comc.push(_exchange_hash[cv]);
		ln += _exchange_hash[cv].length; 
	});
	
	var all = Buffer.concat(comc, ln);
	//SSHPacket.__dump_buffer(all);
	this._exchange_hash = this._hash(all);
	//SSHPacket.__dump_buffer(this._exchange_hash);
	if(!this._session_identifier) this._session_identifier = this._exchange_hash;
	 
	return this._exchange_hash; 
};

SSHKex.prototype._hash = function (buf) {
	var hashf;
	switch(this._kex_algorithm) {
	case 'diffie-hellman-group-exchange-sha256': hashf = crypto.createHash('sha256'); break;	
	}
	if(!hashf) throw new Error('no supporting hash function for ' + this._kex_algorithm);
	hashf.update(buf);
	return new Buffer(hashf.digest(), 'binary');	
};

SSHKex.prototype.recvblocksize = SSHKex.prototype._recv_cblocksize = function () {
	switch(this._recv_encryption_algorithm) {
	case 'aes128-cbc': return 128 / 8;
	case 'aes256-cbc': return 256 / 8;
	default: throw new Error('unknown recv encryption algorithm: ' + this._recv_encryption_algorithm); 
	}
};

SSHKex.prototype.sendblocksize = SSHKex.prototype._send_cblocksize = function () {
	switch(this._send_encryption_algorithm) {
	case 'aes128-cbc': return 128 / 8;
	case 'aes256-cbc': return 256 / 8;
	default: throw new Error('unknown send encryption algorithm: ' + this._send_encryption_algorithm); 
	}
};

SSHKex.prototype.recvhashsize = SSHKex.prototype._recv_mblocksize = function () {
	switch(this._recv_mac_algorithm) {
	case 'hmac-sha1': return 160 / 8;
	case 'hmac-md5': return 128 / 8;
	default: throw new Error('unknown recv mac algorithm: ' + this._recv_mac_algorithm); 
	}
};

SSHKex.prototype.sendhashsize = SSHKex.prototype._send_mblocksize = function () {
	switch(this._send_mac_algorithm) {
	case 'hmac-sha1': return 160 / 8;
	case 'hmac-md5': return 128 / 8;
	default: throw new Error('unknown send mac algorithm: ' + this._send_mac_algorithm); 
	}
};

SSHKex.prototype.sendhmacf = function () {	
	var fname, ik;
	
	switch(this._send_mac_algorithm) {
	case 'hmac-sha1': fname = 'sha1'; ik = this._keys.IK_stoc; break;
	case 'hmac-md5': fname = 'md5'; ik = this._keys.IK_stoc; break;
	default: throw new Error('unknown send mac algorithm: ' + this._send_mac_algorithm); 
	}
	
	return function (buf) {
		var hmac = crypto.createHmac(fname, ik);
		hmac.update(buf);
		return new Buffer(hmac.digest(), 'binary');
	};
};

SSHKex.prototype.recvhmacf = function () {
	var fname, ik;
	
	switch(this._recv_mac_algorithm) {
	case 'hmac-sha1': fname = 'sha1'; ik = this._keys.IK_ctos; break;
	case 'hmac-md5': fname = 'md5'; ik = this._keys.IK_ctos; break;
	default: throw new Error('unknown recv mac algorithm: ' + this._recv_mac_algorithm); 
	}
	
	return function (buf) {
		var hmac = crypto.createHmac(fname, ik);
		hmac.update(buf);
		return new Buffer(hmac.digest(), 'binary');
	};
};

SSHKex.prototype.cipherf = function () {
	var cipherf = null;
	
	switch(this._send_encryption_algorithm) {
	case 'aes128-cbc': cipherf = crypto.createCipheriv('aes-128-cbc', this._keys.EK_stoc, this._keys.IV_stoc); break;
	case 'aes256-cbc': cipherf = crypto.createCipheriv('aes-256-cbc', this._keys.EK_stoc, this._keys.IV_stoc); break;
	default: throw new Error('unknown recv encryption algorithm: ' + this._recv_encryption_algorithm); 
	}
	
	cipherf.setAutoPadding(false);
	
	return function (buf) {
		return new Buffer(cipherf.update(buf), 'binary');
	};
};

SSHKex.prototype.decipherf = function () {
	var decipherf = null;
	
	switch(this._recv_encryption_algorithm) {
	case 'aes128-cbc': decipherf = crypto.createDecipheriv('aes-128-cbc', this._keys.EK_ctos, this._keys.IV_ctos); break;
	case 'aes256-cbc': decipherf = crypto.createDecipheriv('aes-256-cbc', this._keys.EK_ctos, this._keys.IV_ctos); break;
	default: throw new Error('unknown recv encryption algorithm: ' + this._recv_encryption_algorithm); 
	}
	
	decipherf.setAutoPadding(false);
	
	return function (buf) {
		return new Buffer(decipherf.update(buf), 'binary');
	};
};

SSHKex.prototype._dhf = function () {
	return crypto.getDiffieHellman(this._dh_group);
};

SSHKex.prototype._signf = function () {
	switch(this._host_key_algorithm) {
	case 'ssh-rsa': return crypto.createSign('RSA-SHA1');	
	}
};

SSHKex.prototype._error = function (err) {
	throw err;
};

/** 
 *		RFC 4253 SSH Transport Layer Protocol Section 6.6
 */
var verifySSHRSAPublicKey = exports.verifySSHRSAPublicKey = function (pk) {
	var offset = 0;
	var ssh_rsa = SSHPacket.readMPInt(pk, offset);
	offset = ssh_rsa.offset;
	ssh_rsa = ssh_rsa.mpint;
	if(ssh_rsa.toString() !== 'ssh-rsa') return new Erorr('publickey is not in SSH-RSA format');
	
	var e = SSHPacket.readMPInt(pk, offset);
	offset = e.offset;
	e = e.mpint;
	var n = SSHPacket.readMPInt(pk, offset).mpint;
	
	return {
		key: SSHPacket.createString(pk),
		e: e,
		n: n,
		fingerprint: readFingerPrint(pk) 
	};
}

function readFingerPrint (buf) {
	if(!Buffer.isBuffer(buf)) return new Error('parameter is not a buffer');
	
	var md5 = crypto.createHash('md5');
	md5.update(buf);
	var fp = md5.digest('hex').toLowerCase(),
		_fp = [];

	for(var i=1; i<=fp.length; i++)
		if(i%2 === 0) _fp.push(fp.substring(i-2, i));
		
	return _fp.join(':');
}
