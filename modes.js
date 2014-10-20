exports['aes-128-ecb'] = {
  cipher: 'AES',
  key: 16,
  iv: 0,
  mode: 'ECB',
  warn: true
};
exports['aes-192-ecb'] = {
  cipher: 'AES',
  key: 24,
  iv: 0,
  mode: 'ECB',
  warn: true
};
exports['aes-256-ecb'] = {
  cipher: 'AES',
  key: 32,
  iv: 0,
  mode: 'ECB',
  warn: true
};
exports['aes-128-cbc'] = {
  cipher: 'AES',
  key: 16,
  iv: 16,
  mode: 'CBC'
};
exports['aes-192-cbc'] = {
  cipher: 'AES',
  key: 24,
  iv: 16,
  mode: 'CBC'
};
exports['aes-256-cbc'] = {
  cipher: 'AES',
  key: 32,
  iv: 16,
  mode: 'CBC'
};
exports.aes128 = exports['aes-128-cbc'];
exports.aes192 = exports['aes-192-cbc'];
exports.aes256 = exports['aes-256-cbc'];
exports['aes-128-cfb'] = {
  cipher: 'AES',
  key: 16,
  iv: 16,
  mode: 'CFB',
  padding: false
};
exports['aes-192-cfb'] = {
  cipher: 'AES',
  key: 24,
  iv: 16,
  mode: 'CFB',
  padding: false
};
exports['aes-256-cfb'] = {
  cipher: 'AES',
  key: 32,
  iv: 16,
  mode: 'CFB',
  padding: false
};
exports['aes-128-cfb1'] = {
  cipher: 'AES',
  key: 16,
  iv: 16,
  mode: 'CFB',
  padding: false
};
exports['aes-192-cfb1'] = {
  cipher: 'AES',
  key: 24,
  iv: 16,
  mode: 'CFB',
  padding: false
};
exports['aes-256-cfb1'] = {
  cipher: 'AES',
  key: 32,
  iv: 16,
  mode: 'CFB',
  padding: false
};
exports['aes-128-cfb8'] = {
  cipher: 'AES',
  key: 16,
  iv: 16,
  mode: 'CFB',
  padding: false
};
exports['aes-192-cfb8'] = {
  cipher: 'AES',
  key: 24,
  iv: 16,
  mode: 'CFB',
  padding: false
};
exports['aes-256-cfb8'] = {
  cipher: 'AES',
  key: 32,
  iv: 16,
  mode: 'CFB',
  padding: false
};
exports['aes-128-ofb'] = {
  cipher: 'AES',
  key: 16,
  iv: 16,
  mode: 'OFB',
  padding: false
};
exports['aes-192-ofb'] = {
  cipher: 'AES',
  key: 24,
  iv: 16,
  mode: 'OFB',
  padding: false
};
exports['aes-256-ofb'] = {
  cipher: 'AES',
  key: 32,
  iv: 16,
  mode: 'OFB',
  padding: false
};
exports['aes-128-ctr'] = {
  cipher: 'AES',
  key: 16,
  iv: 16,
  mode: 'CTR',
  padding: false
};
exports['aes-192-ctr'] = {
  cipher: 'AES',
  key: 24,
  iv: 16,
  mode: 'CTR',
  padding: false
};
exports['aes-256-ctr'] = {
  cipher: 'AES',
  key: 32,
  iv: 16,
  mode: 'CTR',
  padding: false
};
// exports['aes-128-gcm'] = {
//   cipher: 'AES',
//   key: 16,
//   iv: 12,
//   mode: 'GCM',
//   padding: false
// };
// exports['aes-192-gcm'] = {
//   cipher: 'AES',
//   key: 24,
//   iv: 12,
//   mode: 'CTR',
//   padding: false
// };
// exports['aes-256-gcm'] = {
//   cipher: 'AES',
//   key: 32,
//   iv: 12,
//   mode: 'CTR',
//   padding: false
// };
// exports['aes-128-xts'] = {
//   cipher: 'AES',
//   key: 32,
//   iv: 16,
//   mode: 'CTR',
//   padding: false
// };
// exports['aes-256-xts'] = {
//   cipher: 'AES',
//   key: 64,
//   iv: 16,
//   mode: 'CTR',
//   padding: false
// };