create-cipher
====


Like node's createCipher/createDecipher but with some better defaults

- instead of a single round of md5 with no salt, keys are derived with pbkdf2, a 512 bit random salt, and 500 iterations (with iterations and salt length configurable);
- an hmac of the message is sent at the end and checked.

api
===

```js
var createCipher = require('create-cipher');

exports.Cipher(algorithm, password, iterations=1000, saltLen=512);
exports.Decipher(algorithm, password);
// no need to pass in iterations or saltLen
```