var argon2 = require('.');

module.exports = {
  test_hash: function (assert) {
    "use strict";

    assert.expect(3);

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

    assert.expect(3);

    argon2.encrypt("password", "somesaltwaytoobig", function (err, hash) {
      assert.ok(err, "Error should be defined.");
      assert.equal(err.message, "Salt too long, maximum 16 characters.", "Error message should be equal to expected.");
      assert.equal(undefined, hash, "Hash should not be defined.");
      assert.done();
    });
  },

  test_hash_time_cost: function (assert) {
    "use strict";

    assert.expect(3);

    argon2.encrypt("password", "somesalt", {
      timeCost: 4
    }, function (err, hash) {
      assert.ok(hash, "Hash should be defined.");
      assert.ok(/m=4096,t=4,p=1/.test(hash), "Hash should have correct time cost.");
      assert.equal(undefined, err, "Error should not be defined.");
      assert.done();
    });
  },

  test_hash_memory_cost: function (assert) {
    "use strict";

    assert.expect(3);

    argon2.encrypt("password", "somesalt", {
      memoryCost: 13
    }, function (err, hash) {
      assert.ok(hash, "Hash should be defined.");
      assert.ok(/m=8192,t=3,p=1/.test(hash), "Hash should have correct memory cost.");
      assert.equal(undefined, err, "Error should not be defined.");
      assert.done();
    });
  },

  test_hash_parallelism: function (assert) {
    "use strict";

    assert.expect(3);

    argon2.encrypt("password", "somesalt", {
      parallelism: 2
    }, function (err, hash) {
      assert.ok(hash, "Hash should be defined.");
      assert.ok(/m=4096,t=3,p=2/.test(hash), "Hash should have correct parallelism.");
      assert.equal(undefined, err, "Error should not be defined.");
      assert.done();
    });
  },

  test_hash_all_options: function (assert) {
    "use strict";

    assert.expect(3);

    argon2.encrypt("password", "somesalt", {
      timeCost: 4,
      memoryCost: 13,
      parallelism: 2
    }, function (err, hash) {
      assert.ok(hash, "Hash should be defined.");
      assert.ok(/m=8192,t=4,p=2/.test(hash), "Hash should have correct options.");
      assert.equal(undefined, err, "Error should not be defined.");
      assert.done();
    });
  },

  test_hash_sync: function (assert) {
    "use strict";

    assert.expect(1);

    var hash = argon2.encryptSync("password", "somesalt");
    assert.equal(hash, "$argon2i$m=4096,t=3,p=1$c29tZXNhbHQAAAAAAAAAAA$FHF/OZ0GJpMRAlBmPTqXxw36Ftp87JllALZPcP9w9gs",
      "Hash should be equal to expected.");
    assert.done();
  },

  test_hash_sync_time_cost: function (assert) {
    "use strict";

    assert.expect(1);

    var hash = argon2.encryptSync("password", "somesalt", {
      timeCost: 4
    });
    assert.ok(/m=4096,t=4,p=1/.test(hash),"Hash should have correct time cost.");
    assert.done();
  },

  test_hash_sync_memory_cost: function (assert) {
    "use strict";

    assert.expect(1);

    var hash = argon2.encryptSync("password", "somesalt", {
      memoryCost: 13
    });
    assert.ok(/m=8192,t=3,p=1/.test(hash), "Hash should have correct memory cost.");
    assert.done();
  },

  test_hash_sync_parallelism: function (assert) {
    "use strict";

    assert.expect(1);

    var hash = argon2.encryptSync("password", "somesalt", {
      parallelism: 2
    });
    assert.ok(/m=4096,t=3,p=2/.test(hash), "Hash should have correct parallelism.");
    assert.done();
  },

  test_hash_sync_all_options: function (assert) {
    "use strict";

    assert.expect(1);

    var hash = argon2.encryptSync("password", "somesalt", {
      timeCost: 4,
      memoryCost: 13,
      parallelism: 2
    });
    assert.ok(/m=8192,t=4,p=2/.test(hash),"Hash should have correct options.");
    assert.done();
  },

  test_hash_sync_long_salt: function (assert) {
    "use strict";

    assert.expect(1);

    assert.throws(function () {
      argon2.encryptSync("password", "somesaltwaytoobig")
    }, Error, "Error should be thrown.");
    assert.done();
  },

  test_generate_salt: function (assert) {
    "use strict";

    assert.expect(1);

    argon2.generateSalt(function (err, salt) {
      assert.ok(salt.length <= 16, "Generated salt length should be less than 16.");
      assert.done();
    });
  },

  test_generate_salt_sync: function (assert) {
    "use strict";

    assert.expect(1);

    assert.ok(argon2.generateSaltSync().length <= 16, "Generated salt length should be less than 16.");
    assert.done();
  },

  test_verify_ok: function (assert) {
    "use strict";

    assert.expect(1);

    argon2.verify(
      "$argon2i$m=4096,t=3,p=1$c29tZXNhbHQAAAAAAAAAAA$FHF/OZ0GJpMRAlBmPTqXxw36Ftp87JllALZPcP9w9gs",
      "password", function (err) {
        assert.equal(undefined, err, "Error should be undefined.");
        assert.done();
      });
  },

  test_verify_fail: function (assert) {
    "use strict";

    assert.expect(1);

    argon2.verify(
      "$argon2i$m=4096,t=3,p=1$c29tZXNhbHQAAAAAAAAAAA$FHF/OZ0GJpMRAlBmPTqXxw36Ftp87JllALZPcP9w9gs",
      "passwolrd", function (err) {
        assert.ok(err, "Error should be defined.");
        assert.done();
      });
  },

  test_verify_sync_ok: function (assert) {
    "use strict";

    assert.expect(1);

    assert.equal(true, argon2.verifySync(
      "$argon2i$m=4096,t=3,p=1$c29tZXNhbHQAAAAAAAAAAA$FHF/OZ0GJpMRAlBmPTqXxw36Ftp87JllALZPcP9w9gs",
      "password"));
    assert.done();
  },

  test_verify_sync_fail: function (assert) {
    "use strict";

    assert.expect(1);

    assert.equal(false, argon2.verifySync(
      "$argon2i$m=4096,t=3,p=1$c29tZXNhbHQAAAAAAAAAAA$FHF/OZ0GJpMRAlBmPTqXxw36Ftp87JllALZPcP9w9gs",
      "passwolrd"));
    assert.done();
  }
};
