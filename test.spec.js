var argon2 = require('.');

module.exports = {
  test_hash: function (assert) {
    "use strict";

    argon2.encrypt("password", "somesalt", function (err, hash) {
      assert.ok(hash, "Hash should be defined.");
      assert.equal(hash,
        "$argon2i$m=4096,t=3,p=1$c29tZXNhbHQAAAAAAAAAAA$FHF/OZ0GJpMRAlBmPTqXxw36Ftp87JllALZPcP9w9gs",
        "Hash should be equal to expected.");
      assert.done();
    });
  }
};
