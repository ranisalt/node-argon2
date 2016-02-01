const bindings = require('bindings')('argon2');
const crypto = require('crypto');

const defaults = Object.freeze({
  timeCost: 3,
  memoryCost: 12,
  parallelism: 1,
  argon2d: false
});

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

const validate = (salt, options, callback) => {
  'use strict';

  if (salt.length !== 16) {
    fail('Invalid salt length, must be 16 bytes.', callback);
    return false;
  }

  for (const key of Object.keys(defaults)) {
    options[key] = options[key] || defaults[key];
  }

  if (isNaN(options.timeCost)) {
    fail('Invalid time cost, must be a number.', callback);
    return false;
  } else if (options.timeCost <= 0) {
    fail('Time cost too low, minimum of 1.', callback);
    return false;
  } else if (options.timeCost >= 4294967296) {
    fail('Time cost too high, maximum of 4294967295.', callback);
    return false;
  }

  if (isNaN(options.memoryCost)) {
    fail('Invalid memory cost, must be a number.', callback);
    return false;
  } else if (options.memoryCost <= 0) {
    fail('Memory cost too low, minimum of 1.', callback);
    return false;
  } else if (options.memoryCost >= 32) {
    fail('Memory cost too high, maximum of 31.', callback);
    return false;
  }

  if (isNaN(options.parallelism)) {
    fail('Invalid parallelism, must be a number.', callback);
    return false;
  } else if (options.parallelism <= 0) {
    fail('Parallelism too low, minimum of 1.', callback);
    return false;
  } else if (options.parallelism >= 4294967296) {
    fail('Parallelism too high, maximum of 4294967295.', callback);
    return false;
  }

  options.argon2d = !!options.argon2d;

  return true;
};

module.exports = {
  defaults,

  hash (plain, salt, options, callback) {
    'use strict';

    if (!Buffer.isBuffer(salt)) {
      salt = new Buffer(salt);
    }

    if (!callback) {
      callback = options;
      options = defaults;
    }

    options = Object.assign({}, options);

    if (validate(salt, options, callback)) {
      return bindings.hash(plain, salt, options.timeCost, options.memoryCost,
        options.parallelism, options.argon2d, callback);
    }
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

    return crypto.randomBytes(16, callback);
  },

  generateSaltSync () {
    'use strict';

    return crypto.randomBytes(16);
  },

  verify (hash, plain, callback) {
    'use strict';

    return bindings.verify(hash, plain, /argon2d/.test(hash), callback);
  },

  verifySync (hash, plain) {
    'use strict';

    return bindings.verifySync(hash, plain, /argon2d/.test(hash));
  }
};
