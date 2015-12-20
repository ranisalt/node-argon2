var bindings = require("bindings")("argon2_lib");

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

exports.verify = function (encrypted, plain, callback) {
  "use strict";

  return bindings.verify(encrypted, plain, callback);
};

exports.verifySync = function (encrypted, plain) {
  "use strict";

  return bindings.verifySync(encrypted, plain);
};

