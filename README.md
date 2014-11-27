durin
=====

> Speak, friend, and enter.

*from inscription on Doors of Durin*

The `durin` module provides functions for hashing passwords.

 * uses standard `crypto.pbkdf2` function
 * salted hashes (no need to save salt separately)
 * hash encoding is URL safe
 * self-describing hash allows simple rehashing to keep hash secure

Example - Hash a password
-------------------------
```js
var durin = require("durin"),
    passwd = "s3kr3t!";

durin.hashPassword(passwd, function(hash) {
    // ... save hash so that the password can be verified later
});
```

Example - Verify a password
---------------------------
```js
var durin = require("durin"),
    passwd = "s3kr3t!",
    hash = "pbkdf2$73$1$8a";

durin.verifyPassword(passwd, hash, function(verified) {
    // verified will be truthy if password matches
    if (verified) {
        // verified will match hash if hash is still secure; otherwise, verified
        // will be set to a new, secure hash
        if (verified !== hash) {
            // ... replace stored hash with new hash
        }
        
        // ... accept login, password matched
    }
    
    // verified set to false if password did not match
    else {
        // ... reject login; password did not match hash
    }
});
```

Example - Configure hash security
---------------------------------
```js
var durin = require("durin")({
        iterations: 125000,
        saltLength: 32,
        keyLength: 512   
    });
```

API
---

### durin(opts)
Create a new durin context with updated options.  Unspecified options will be
inherited from the executed durin context.

**opts.iterations**

Number of iterations to use for a new hash.  When verifying an existing hash,
this is the minimum number of iterations for a hash to be considered secure.

**opts.keyLength**

Number of bits to use for a new hash key.  When verifying an existing hash,
this is the minimum number of bits in a key for a hash to be considered secure.

**opts.saltLength**

Number of bits to use for salting a new hash.  When verifying an existing hash,
this is the minimum number of bits in a salt for a hash to be considered secure.

### durin.hashPassword(password, done)
Hash the password.  The callback gets the argument `(hash)`

### durin.isHash(val)
Return true if the value is a recognized hash.

### durin.iterations
Read-only.  The value of the iterations option for the durin context.

### durin.keyLength
Read-only.  The value of the keyLength option for the durin context.

### durin.saltLength
Read-only.  The value of the saltLength option for the durin context.

### durin.verifyPassword(password, hash, done)
Verify a password.  The callback gets a single argument `(verified)`, which
is false if the password could not be verified.  If the password is verified,
the passed value will be the hash, which may be updated to meet configured
security requirements.

