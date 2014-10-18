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
  saltLen = saltLen || 512;
  var saltIter = new Buffer(8);
  saltIter.writeUInt32BE(iterations, 0);
  saltIter.writeUInt32BE(saltLen, 4);
  this.push(saltIter);
  var salt = crypto.randomBytes(saltLen);
  this.push(salt);
  this._cipher = void 0;
  var mode = modes[suite];
  var len = mode.key + mode.iv + mode.key;
  var self = this;
  crypto.pbkdf2(password, salt, iterations, len, function (err, resp) {
    if (err) {
      return self.emit('error', err);
    }
    var key = resp.slice(0, mode.key);
    var iv = resp.slice(mode.key, mode.key + mode.iv);
    self._cipher = crypto.createCipheriv(suite, key, iv);
    self._hash = crypto.createHmac('sha512', resp.slice(mode.key + mode.iv));
    self.emit('cipher-ready');
  });
}
Cipher.prototype._transform = function (chunk, _, next) {
  var self = this;
  
  if (!this._cipher) {
    this.once('cipher-ready', function () {
      this._hash.update(chunk);
      var result = self._cipher.update(chunk);
      if (result) {
        self.push(result);
      }
      next();
    });
  } else {
    this._hash.update(chunk);
    var result = self._cipher.update(chunk);
    if (result) {
      self.push(result);
    }
    next();
  }
};
Cipher.prototype._flush = function (next) {
  var out = this._cipher.final();
  if (out) {
    this.push(out);
  }
  var hash = this._hash.digest();
  this.push(hash);
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
  var len = mode.key + mode.iv + mode.key;
  var self = this;
  this._cache = new Buffer('');
  
  this._makesuite = function (salt, cb) {
      crypto.pbkdf2(password, salt, self._iterations, len, function (err, resp) {
      if (err) {
        return cb(err);
      }
      var key = resp.slice(0, mode.key);
      var iv = resp.slice(mode.key, mode.key + mode.iv);
      self._cipher = crypto.createDecipheriv(suite, key, iv);
      self._hash = crypto.createHmac('sha512', resp.slice(mode.key + mode.iv));
      cb();
    });
  };

}
Decipher.prototype._transform = function (chunk, _, next) {
  var self = this;
  this._cache = Buffer.concat([this._cache, chunk]);
  if (this._cache.length < 64) {
    return next();
  } else {
    chunk = this._cache.slice(0, this._cache.length - 64);
    this._cache = this._cache.slice(this._cache.length - 64);
  }
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
    return this._makesuite(salt, function (err) {
      if (err) {
        return next(err);
      }
      if (data) {
        var result = self._cipher.update(data);
        if (result) {
          self._hash.update(result);
          self.push(result);
        }
      }
      next();
    });
  } else {
    var result = self._cipher.update(chunk);
    if (result) {
      self._hash.update(result);
      self.push(result);
    }
    next();
  }
};
Decipher.prototype._flush = function (next) {
  var tail = this._cipher.final();
  if (tail) {
    this._hash.update(tail);
    this.push(tail);
  }
  var out = xor(this._hash.digest(), this._cache);
  var sum = 0;
  var i = -1;
  var len = out.length;
  while (++i < len) {
    sum += out[i];
  }
  if (sum) {
    return next(new Error('did not match'));
  }
  next();
};
function xor(a, b) {
  var len = Math.min(a.length, b.length);
  var out = new Buffer(len);
  var i = -1;
  while (++i < len) {
    out.writeUInt8(a[i] ^ b[i], i);
  }
  return out;
}