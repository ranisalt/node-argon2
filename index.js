var bindings = require("bindings")("argon2_lib");

exports.encrypt = function (plain, salt, callback) {
  "use strict";

  if (salt.length < 16) {
    callback(new Error("Salt too long, maximum 16 characters."), null);
    return;
  }

  return bindings.encrypt(plain, salt, callback);
};
