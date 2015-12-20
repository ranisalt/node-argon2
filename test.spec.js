var argon2 = require('.');

module.exports = {
  test_hash: function (assert) {
    "use strict";

    argon2.encrypt("password", "somesalt", function (err, hash) {
      assert.ok(hash, "Hash should be defined.");
      assert.equal(hash, "$argon2i$m=4096,t=3,p=1$c29tZXNhbHQAAAAAAAAAAA$FHF/OZ0GJpMRAlBmPTqXxw36Ftp87JllALZPcP9w9gs",
        "Hash should be equal to expected.");
      assert.equal(undefined, err, "Error should not be defined.");
      assert.done();
    });
  },

  test_hash_long_salt: function (assert) {
    "use strict";

    argon2.encrypt("password", "somesaltwaytoobig", function (err, hash) {
      assert.ok(err, "Error should be defined.");
      assert.equal(err.message, "Salt too long, maximum 16 characters.", "Error message should be equal to expected.");
      assert.equal(undefined, hash, "Hash should not be defined.");
      assert.done();
    });
  },

  test_hash_sync: function (assert) {
    "use strict";

    var hash = argon2.encryptSync("password", "somesalt");
    assert.equal(hash, "$argon2i$m=4096,t=3,p=1$c29tZXNhbHQAAAAAAAAAAA$FHF/OZ0GJpMRAlBmPTqXxw36Ftp87JllALZPcP9w9gs",
        "Hash should be equal to expected.");
    assert.done();
  },

  test_hash_sync_long_salt: function (assert) {
    "use strict";

    assert.throws(function() {
      argon2.encryptSync("password", "somesaltwaytoobig")
    }, Error, "Error should be thrown.");
    assert.done();
  },

  test_verify_ok: function (assert) {
    "use strict";

    argon2.verify(
      "$argon2i$m=4096,t=3,p=1$c29tZXNhbHQAAAAAAAAAAA$FHF/OZ0GJpMRAlBmPTqXxw36Ftp87JllALZPcP9w9gs",
      "password", function (err) {
        assert.equal(undefined, err, "Error should be undefined.");
        assert.done();
      });
  },

  test_verify_fail: function (assert) {
    "use strict";

    argon2.verify(
      "$argon2i$m=4096,t=3,p=1$c29tZXNhbHQAAAAAAAAAAA$FHF/OZ0GJpMRAlBmPTqXxw36Ftp87JllALZPcP9w9gs",
      "passwolrd", function (err) {
        assert.ok(err, "Error should be defined.");
        assert.done();
      });
  },

  test_verify_sync_ok: function (assert) {
    "use strict";

    assert.equal(true, argon2.verifySync(
      "$argon2i$m=4096,t=3,p=1$c29tZXNhbHQAAAAAAAAAAA$FHF/OZ0GJpMRAlBmPTqXxw36Ftp87JllALZPcP9w9gs",
      "password"));
    assert.done();
  },

  test_verify_sync_fail: function (assert) {
    "use strict";

    assert.equal(false, argon2.verifySync(
      "$argon2i$m=4096,t=3,p=1$c29tZXNhbHQAAAAAAAAAAA$FHF/OZ0GJpMRAlBmPTqXxw36Ftp87JllALZPcP9w9gs",
      "passwolrd"));
    assert.done();
  }
};
