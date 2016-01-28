var bindings = require("bindings")("argon2"),
  crypto = require("crypto");

var defaults = exports.defaults = Object.freeze({
  timeCost: 3,
  memoryCost: 12,
  parallelism: 1,
  argon2d: false
});

var fail = function (message, callback) {
  var error = new Error(message);

  if (typeof(callback) === "undefined") {
    throw error;
  } else {
    process.nextTick(function () {
      callback(error, null);
    });
  }
};

var validate = function (salt, options, callback) {
  if (salt.length > 16) {
    fail("Salt too long, maximum 16 characters.", callback);
    return false;
  }

  Object.assign(options, Object.assign({}, defaults, options));

  if (isNaN(options.timeCost)) {
    fail("Invalid time cost, must be a number.", callback);
    return false;
  }

  if (options.timeCost <= 0) {
    fail("Time cost too low, minimum of 1.", callback);
    return false;
  }

  if (options.timeCost >= 4294967296) {
    fail("Time cost too high, maximum of 4294967295.", callback);
    return false;
  }

  if (isNaN(options.memoryCost)) {
    fail("Invalid memory cost, must be a number.", callback);
    return false;
  }

  if (options.memoryCost <= 0) {
    fail("Memory cost too low, minimum of 1.", callback);
    return false;
  }

  if (options.memoryCost >= 32) {
    fail("Memory cost too high, maximum of 31.", callback);
    return false;
  }

  if (isNaN(options.parallelism)) {
    fail("Invalid parallelism, must be a number.", callback);
    return false;
  }

  if (options.parallelism <= 0) {
    fail("Parallelism too low, minimum of 1.", callback);
    return false;
  }

  if (options.parallelism >= 4294967296) {
    fail("Parallelism too high, maximum of 4294967295.", callback);
    return false;
  }

  options.argon2d = !!options.argon2d;

  return true;
};

exports.hash = function (plain, salt, options, callback) {
  "use strict";

  if (!callback) {
    callback = options;
    options = {};
  }

  if (validate(salt, options, callback)) {
    return bindings.hash(plain, salt, options.timeCost, options.memoryCost,
      options.parallelism, options.argon2d, callback);
  }
};

exports.hashSync = function (plain, salt, options) {
  "use strict";

  options = options || {};

  if (validate(salt, options)) {
    return bindings.hashSync(plain, salt, options.timeCost, options.memoryCost,
        options.parallelism, options.argon2d);
  }
};

exports.generateSalt = function (callback) {
  "use strict";

  crypto.randomBytes(16, function (err, buffer) {
    callback(err, buffer.toString());
  });
};

exports.generateSaltSync = function () {
  "use strict";

  return crypto.randomBytes(16).toString();
};

exports.verify = function (hash, plain, callback) {
  "use strict";

  return bindings.verify(hash, plain, /argon2d/.test(hash), callback);
};

exports.verifySync = function (hash, plain) {
  "use strict";

  return bindings.verifySync(hash, plain, /argon2d/.test(hash));
};

