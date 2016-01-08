var bindings = require("bindings")("argon2_lib"),
  crypto = require("crypto");

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

  options.timeCost = options.timeCost || 3;
  options.memoryCost = options.memoryCost || 12;
  options.parallelism = options.parallelism || 1;
  options.argon2d = !!options.argon2d;

  if (isNaN(options.timeCost)) {
    fail("Invalid time cost, must be a number.", callback);
    return false;
  }

  if (isNaN(options.memoryCost)) {
    fail("Invalid memory cost, must be a number.", callback);
    return false;
  }

  if (options.memoryCost >= 32) {
    fail("Memory cost too high, maximum of 32.", callback);
    return false;
  }

  if (isNaN(options.parallelism)) {
    fail("Invalid parallelism, must be a number.", callback);
    return false;
  }

  return true;
};

exports.encrypt = function (plain, salt, options, callback) {
  "use strict";

  if (!callback) {
    callback = options;
    options = {};
  }

  if (validate(salt, options, callback)) {
    return bindings.encrypt(plain, salt, options.timeCost, options.memoryCost,
      options.parallelism, options.argon2d, callback);
  }
};

exports.encryptSync = function (plain, salt, options) {
  "use strict";

  options = options || {};

  if (validate(salt, options)) {
    return bindings.encryptSync(plain, salt, options.timeCost,
      options.memoryCost, options.parallelism, options.argon2d);
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

exports.verify = function (encrypted, plain, callback) {
  "use strict";

  return bindings.verify(encrypted, plain, /argon2d/.test(encrypted), callback);
};

exports.verifySync = function (encrypted, plain) {
  "use strict";

  return bindings.verifySync(encrypted, plain, /argon2d/.test(encrypted));
};

