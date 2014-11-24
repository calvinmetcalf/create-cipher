var crypto = require('crypto');
var Transform = require('readable-stream').Transform;
var inherits = require('inherits');
var modes = require('./modes');

inherits(Cipher, Transform);
exports.Cipher = Cipher;
function Cipher(suite, password, iterations, saltLen) {
  if (!(this instanceof Cipher)) {
    return new Cipher(suite, password, iterations);
  }
  Transform.call(this);
  iterations = iterations || 1000;
  saltLen = saltLen || 16;
  this._saltIter = new Buffer(8);
  this._saltIter.writeUInt32BE(iterations, 0);
  this._saltIter.writeUInt32BE(saltLen, 4);
  var salt = this._salt = crypto.randomBytes(saltLen);
  this._cipher = void 0;
  var mode = modes[suite];
  if (mode.warn) {
    console.warn(suite, 'is not secure, do not use in production');
  }
  var len = mode.key + mode.iv;
  var self = this;
  var resp = crypto.pbkdf2Sync(password, salt, iterations, len);

  var key = resp.slice(0, mode.key);
  var iv = resp.slice(mode.key);
  self._cipher = crypto.createCipheriv(suite, key, iv);
}
Cipher.prototype.update = function(chunk, inEnc, outEnc) {
  return this._cipher.update(chunk, inEnc, outEnc);
};
Cipher.prototype.final = function(chunk, outEnc) {
  return this._cipher.final(chunk, outEnc);
};
Cipher.prototype._transform = function (chunk, _, next) {
  if (this._saltIter) {
    this.push(this._saltIter);
    this._saltIter = null;
    this.push(this._salt);
  }
  var result = this._cipher.update(chunk);
  if (result) {
    this.push(result);
  }
  next();
};
Cipher.prototype._flush = function (next) {
  var out = this._cipher.final();
  if (out) {
    this.push(out);
  }
  next();
};
inherits(Decipher, Transform);
exports.Decipher = Decipher;
function Decipher(suite, password) {
  if (!(this instanceof Decipher)) {
    return new Decipher(suite, password);
  }
  Transform.call(this);
  this._iterations = void 0;
  this._saltLen = void 0;
  this._salt = new Buffer('');
  this._cipher = void 0;
  var mode = modes[suite];
  var len = mode.key + mode.iv;
  var self = this;
  
  this._makesuite = function (salt) {
    var resp = crypto.pbkdf2Sync(password, salt, self._iterations, len);
    var key = resp.slice(0, mode.key);
    var iv = resp.slice(mode.key);
    self._cipher = crypto.createDecipheriv(suite, key, iv);
  };

}
Decipher.prototype._transform = function (chunk, _, next) {
  var self = this;
  if (!this._cipher) {
    this._salt = Buffer.concat([this._salt, chunk]);
    if (!this._saltLen) {
      if (this._salt.length < 8) {
        return next();
      }
      this._iterations = this._salt.readUInt32BE(0);
      this._saltLen = this._salt.readUInt32BE(4);
      this._salt = this._salt.slice(8);
    }
    if (this._salt.length < this._saltLen) {
      return next();
    }
    var salt = this._salt.slice(0, this._saltLen);
    var data;
    if (this._saltLen < this._salt.length) {
      data = this._salt.slice(this._saltLen);
    }
    this._makesuite(salt);
    if (data) {
      var res = self._cipher.update(data);
      if (res) {
        self.push(res);
      }
    }
    return next();
  } else {
    var result = self._cipher.update(chunk);
    if (result) {
      self.push(result);
    }
    next();
  }
};
Decipher.prototype._flush = function (next) {
  var tail = this._cipher.final();
  if (tail) {
    this.push(tail);
  }
  next();
};
Decipher.prototype.update = function(chunk, inEnc, outEnc) {
  return this._cipher.update(chunk, inEnc, outEnc);
};
Decipher.prototype.final = function(chunk, outEnc) {
  return this._cipher.final(chunk, outEnc);
};