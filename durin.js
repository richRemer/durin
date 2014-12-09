var pbkdf2 = require("crypto").pbkdf2,
    randomBytes = require("crypto").randomBytes,
    copy = require("objektify").copy,
    prop = require("propertize"),
    hashOptions = {};

// iterations should grow as hardware improves; double every two years
hashOptions.iterations = 1000 << Math.floor((new Date().getFullYear()-2000)/2);

// hearsay indicates this is recommended in the "standard"
hashOptions.saltLength = 64;

// chosen because it seems reasonable
hashOptions.keyLength = 128;

/**
 * Parse hash into a hash object.  Return the hash object, or false if the hash
 * format is not recognized.
 * @param {string} hash
 * @returns {object}
 */
function parseHash(hash) {
    var tokens = hash.split("$"),
        result = {};

    try {
        if (tokens.length < 4) return false;

        result.algorithm = tokens.shift();
        result.salt = new Buffer(tokens.shift(), "hex").toString("binary");
        result.iterations = parseInt(tokens.shift());
        result.key = new Buffer(tokens.shift(), "hex").toString("binary");
        result.comment = tokens.join("$");
        
        if (result.algorithm !== "pbkdf2") return false;
        if (isNaN(result.iterations) || result.iterations <= 0) return false;
        
        return result;
    } catch (e) {
        return false;
    }
}

/**
 * Return true if the string is a recognized hash.
 * @param {string} hash
 * @returns {boolean}
 */
function isHash(hash) {
    return !!parseHash(hash);
}

/**
 * Hash a password and pass the hash to the callback.
 * @param {object} opts
 * @param {string} password
 * @param {function} done
 */
function hashPassword(opts, password, done) {
    var salt = randomBytes(opts.saltLength >> 3),
        iters = opts.iterations;
    
    pbkdf2(password, salt, iters, opts.keyLength >> 3, function(err, key) {
        var hash = "pbkdf2$";
        
        if (err) throw err;
        
        hash += salt.toString("hex") + "$";
        hash += iters.toString(10) + "$";
        hash += key.toString("hex");

        done(hash);
    });
}

/**
 * Verify password against a hash, and generate an updated hash if the hash
 * does not meet configured security requirements.  Pass the original or
 * updated hash to the callback, or false if the password cannot be verified.
 * @param {object} opts
 * @param {string} password
 * @param {string} hash
 * @param {function} done
 */
function verifyPassword(opts, password, hash, done) {
    var H = parseHash(hash),
        rehash = false;

    if (!H) return done(false);

    if (H.salt.length << 3 < opts.saltLength) rehash = true;
    if (H.key.length << 3 < opts.keyLength) rehash = true;
    if (H.iterations < opts.iterations) rehash = true;

    pbkdf2(password, H.salt, H.iterations, H.key.length, function(err, key) {
        if (err) throw err;
        
        if (key.toString("binary") === H.key) {
            if (rehash) {
                opts.saltLength = Math.max(opts.saltLength, H.salt.length << 3);
                opts.keyLength = Math.max(opts.keyLength, H.key.length << 3);
                opts.iterations = Math.max(opts.iterations, H.iterations);
                hashPassword(opts, password, done);
            } else done(hash);
        } else {
            done(false);
        }
    });
}

/**
 * Create a new durin context.
 * @param {object} opts
 * @returns {function}
 */
function createContext(opts) {
    var result = function(newopts) {
        var combinedOpts = {};
        copy(combinedOpts, opts);
        copy(combinedOpts, newopts);
        return createContext(combinedOpts);
    }
    
    result.isHash = isHash;
    result.hashPassword = hashPassword.bind(null, opts);
    result.verifyPassword = verifyPassword.bind(null, opts);
    prop.readonly(result, "iterations", opts.iterations);
    prop.readonly(result, "saltLength", opts.saltLength);
    prop.readonly(result, "keyLength", opts.keyLength);
    
    return result;
}

/** export default context */
module.exports = createContext(hashOptions);
