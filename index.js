const bindings = require('bindings')('argon2');
const crypto = require('crypto');

const defaults = Object.freeze({
  timeCost: 3,
  memoryCost: 12,
  parallelism: 1,
  argon2d: false
});

const limits = Object.freeze(bindings.limits);

const validate = (salt, options) => {
  'use strict';

  if (!Buffer.isBuffer(salt) || salt.length < 8) {
    throw new Error('Invalid salt, must be a buffer with 8 or more bytes.');
  }

  if (options.parallelism === 'auto') {
    options.parallelism = require('os').cpus().length;
  }

  for (const key of Object.keys(limits)) {
    const max = limits[key].max;
    const min = limits[key].min;
    const value = options[key];
    if (!Number.isInteger(value) || value > max || value < min) {
      throw new Error(`Invalid ${key}, must be an integer between ${min} and ${max}.`);
    }
  }
};

module.exports = {
  defaults, limits,

  hash(plain, salt, options) {
    'use strict';

    options = Object.assign({}, defaults, options);

    if (!Buffer.isBuffer(plain)) {
      plain = new Buffer(plain);
    }

    try {
      validate(salt, options);
      return bindings.hash(plain, salt, options.timeCost, options.memoryCost,
          options.parallelism, options.argon2d);
    } catch (err) {
      return Promise.reject(err);
    }
  },

  hashSync(plain, salt, options) {
    'use strict';

    console.warn('The synchronous API is deprecated, use ES6 await instead.');
    options = Object.assign({}, defaults, options);

    if (!Buffer.isBuffer(plain)) {
      plain = new Buffer(plain);
    }

    validate(salt, options);
    return bindings.hashSync(plain, salt, options.timeCost, options.memoryCost,
        options.parallelism, options.argon2d);
  },

  generateSalt(length) {
    'use strict';

    length = typeof length === 'undefined' ? 16 : length;
    return new Promise((resolve, reject) => {
      crypto.randomBytes(length, (err, salt) => {
        /* istanbul ignore if */
        if (err) {
          return reject(err);
        }
        return resolve(salt);
      });
    });
  },

  generateSaltSync(length) {
    'use strict';

    console.warn('The synchronous API is deprecated, use ES6 await instead.');
    length = typeof length === 'undefined' ? 16 : length;
    return crypto.randomBytes(length);
  },

  verify(hash, plain) {
    'use strict';

    if (!Buffer.isBuffer(hash)) {
      hash = new Buffer(hash);
    }

    if (!Buffer.isBuffer(plain)) {
      plain = new Buffer(plain);
    }

    return bindings.verify(hash, plain, /argon2d/.test(hash));
  },

  verifySync(hash, plain) {
    'use strict';

    console.warn('The synchronous API is deprecated, use ES6 await instead.');

    if (!Buffer.isBuffer(hash)) {
      hash = new Buffer(hash);
    }

    if (!Buffer.isBuffer(plain)) {
      plain = new Buffer(plain);
    }

    return bindings.verifySync(hash, plain, /argon2d/.test(hash));
  }
};
