var bindings = require("bindings")("argon2_lib"),
  crypto = require("crypto");

exports.encrypt = function (plain, salt, callback) {
  "use strict";

  if (salt.length > 16) {
    process.nextTick(function () {
      callback(new Error("Salt too long, maximum 16 characters."), null);
    });
    return;
  }

  return bindings.encrypt(plain, salt, callback);
};

exports.encryptSync = function (plain, salt) {
  "use strict";

  if (salt.length > 16) {
    throw new Error("Salt too long, maximum 16 characters.");
  }

  return bindings.encryptSync(plain, salt);
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

