var bindings = require("bindings")("argon2_lib"),
  crypto = require("crypto");

exports.encrypt = function (plain, salt, options, callback) {
  "use strict";

  if (typeof(callback) == 'undefined') {
    callback = options;
    options = {};
  }

  options.timeCost = options.timeCost || 3;
  options.memoryCost = options.memoryCost || 12;
  options.parallelism = options.parallelism || 1;

  if (salt.length > 16) {
    process.nextTick(function () {
      callback(new Error("Salt too long, maximum 16 characters."), null);
    });
    return;
  }

  if (options.memoryCost >= 32) {
    process.nextTick(function() {
      callback(new Error("Memory cost too high, maximum of 32"), null);
    });
  }

  return bindings.encrypt(plain, salt, options.timeCost, options.memoryCost,
    options.parallelism, callback);
};

exports.encryptSync = function (plain, salt, options) {
  "use strict";

  options = options || {};

  options.timeCost = options.timeCost || 3;
  options.memoryCost = options.memoryCost || 12;
  options.parallelism = options.parallelism || 1;

  if (salt.length > 16) {
    throw new Error("Salt too long, maximum 16 characters.");
  }

  if (options.memoryCost >= 32) {
    throw new Error("Memory cost too high, maximum of 32");
  }

  return bindings.encryptSync(plain, salt, options.timeCost, options.memoryCost,
    options.parallelism);
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

  return bindings.verify(encrypted, plain, callback);
};

exports.verifySync = function (encrypted, plain) {
  "use strict";

  return bindings.verifySync(encrypted, plain);
};

