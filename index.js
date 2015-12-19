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

exports.verify = function (encrypted, plain, callback) {
  "use strict";

  return bindings.verify(encrypted, plain, callback);
}
