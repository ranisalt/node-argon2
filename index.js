const bindings = require('bindings')('argon2');
const crypto = require('crypto');

const defaults = Object.freeze({
  timeCost: 3,
  memoryCost: 12,
  parallelism: 1,
  argon2d: false
});

const limits = Object.freeze(bindings.limits);

const defineValue = (value, def) => {
  'use strict';

  return (typeof value === 'undefined') ? def : value;
};

const fail = (message, callback) => {
  'use strict';

  const error = new Error(message);

  if (typeof callback === 'undefined') {
    throw error;
  } else {
    process.nextTick(() => {
      callback(error, null);
    });
  }
};

const validateInteger = (value, limits) => {
  'use strict';

  return Number.isInteger(value) && value <= limits.max && value >= limits.min;
};

const validate = (salt, options, callback) => {
  'use strict';

  if (salt.length !== 16) {
    fail('Invalid salt length, must be 16 bytes.', callback);
    return false;
  }

  for (const key of Object.keys(limits)) {
    options[key] = defineValue(options[key], defaults[key]);

    const current = limits[key];
    if (!validateInteger(options[key], current)) {
      fail(`Invalid ${current.description}, must be an integer between `
        + `${current.min} and ${current.max}.`, callback);
      return false;
    }
  }

  options.argon2d = !!options.argon2d;

  return true;
};

module.exports = {
  defaults, limits,

  hash (plain, salt, options, callback) {
    'use strict';

    if (!Buffer.isBuffer(salt)) {
      salt = new Buffer(salt);
    }

    if (typeof options === 'function') {
      callback = options;
      options = defaults;
    }

    options = Object.assign({}, options);

    const promise = new Promise((resolve, reject) => {
      if (validate(salt, options, reject)) {
        bindings.hash(plain, salt, options.timeCost, options.memoryCost,
          options.parallelism, options.argon2d, (err, hash) => {
            if (err) {
              reject(err);
            } else {
              resolve(hash);
            }
          });
      }
    });

    if (typeof callback === 'function') {
      promise
        .then((hash) => callback(undefined, hash))
        .catch((error) => callback(error, null));
    }

    return promise;
  },

  hashSync (plain, salt, options) {
    'use strict';

    if (!Buffer.isBuffer(salt)) {
      salt = new Buffer(salt);
    }

    options = Object.assign({}, options || defaults);

    if (validate(salt, options)) {
      return bindings.hashSync(plain, salt, options.timeCost,
        options.memoryCost, options.parallelism, options.argon2d);
    }
  },

  generateSalt (callback) {
    'use strict';

    const promise = new Promise((resolve, reject) => {
      crypto.randomBytes(16, (err, salt) => {
        if (err) {
          reject(err);
        } else {
          resolve(salt);
        }
      });
    });

    if (typeof callback === 'function') {
      promise
        .then((hash) => callback(undefined, hash))
        .catch((error) => callback(error, null));
    }

    return promise;
  },

  generateSaltSync () {
    'use strict';

    return crypto.randomBytes(16);
  },

  verify (hash, plain, callback) {
    'use strict';

    const promise = new Promise((resolve, reject) => {
      bindings.verify(hash, plain, /argon2d/.test(hash), (err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });

    if (typeof callback === 'function') {
      promise
        .then((hash) => callback(undefined, hash))
        .catch((error) => callback(error, null));
    }

    return promise;
  },

  verifySync (hash, plain) {
    'use strict';

    return bindings.verifySync(hash, plain, /argon2d/.test(hash));
  }
};
