create-cipher [![Build Status](https://travis-ci.org/calvinmetcalf/create-cipher.svg)](https://travis-ci.org/calvinmetcalf/create-cipher)
====


# Whats wrong with crypto.createCipher?

The issues with the default node `crypto.createCiphe`r is that it uses a weak and deterministic method of creating a cipher key and initialization vector from your supplied password.  There isn't anything wrong with crypto.createCipheriv and if you used `crypto.randomByte` to create your password you'd also be fine. Node core team members [are aware](https://github.com/joyent/node/issues/8578) and there should be a [better docs](https://github.com/joyent/node/pull/8580) soon.

`cryto.createCipher` generates the key and iv from your password without a salt and using an [outdated OpenSSL function](https://www.openssl.org/docs/crypto/EVP_BytesToKey.html), it also only uses only one iteration and md5.  The worst problem and the one hardest to solve is the lack of salt, from the OpenSSL docs:

> Without the -salt option it is possible to perform efficient dictionary attacks on the password and to attack stream cipher encrypted data. The reason for this is that without the salt the same password always generates the same encryption key.

This is the hardest to solve for node because it has no mechanism to communicate the salt along with the message without destroying backwards compatibility.  The other issues of using a non cryptographically secure hash function (md5) and iteration count of 1 make it more feasible to quickly generate keys and ivs dynamically to test a cipher text with.  For details of how feasible it is to do an attack like this see [this Ars Technica article](http://arstechnica.com/security/2012/08/passwords-under-assault/) about cracking password hashes.  

# What this does

Instead of a single round of md5 with no salt, keys are derived with pbkdf2, a 16 byte random salt, and 1000 iterations (with iterations and salt length configurable). The salt (along with info on the salt length and iteration count) is sent in a header before the encrypted text so all that is needed to know to decrypt the text is the algorithm and password.

# API

Similar to crypto.createCipher but 

- just a regular stream
- two additional (optional) arguments, iterations and saltLen.

```js
var createCipher = require('create-cipher');

createCipher.Cipher(algorithm, password, iterations=1000, saltLen=16);
createCipher.Decipher(algorithm, password);
// no need to pass in iterations or saltLen
```



# Versions

- 1.0.0: first published
- 2.0.0: switched the hash at the end of the message to an hmac
- 2.1.0: changes the default salt length from 512 bytes to 16 bytes
- 3.0.0 removed the hmac, was done poorly and off focus.