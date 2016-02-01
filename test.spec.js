const argon2 = process.env.COVERAGE
  ? require('./index-cov')
  : require('./index');

const password = 'password';
const salt = new Buffer(16);
salt.fill(0).write('somesalt');

module.exports = {
  test_defaults  (assert) {
    'use strict';

    assert.expect(1);

    assert.deepEqual(argon2.defaults, {
      timeCost: 3,
      memoryCost: 12,
      parallelism: 1,
      argon2d: false
    });
    assert.done();
  },

  test_hash  (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, salt, (err, hash) => {
      assert.ok(hash, 'Hash should be defined.');
      assert.equal(hash, '$argon2i$m=4096,t=3,p=1$c29tZXNhbHQAAAAAAAAAAA$FHF/OZ0GJpMRAlBmPTqXxw36Ftp87JllALZPcP9w9gs');
      assert.equal(undefined, err);
      assert.done();
    });
  },

  test_hash_argon2d (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, salt, {
      argon2d: true
    }, (err, hash) => {
      assert.ok(hash, 'Hash should be defined.');
      assert.ok(/\$argon2d\$/.test(hash), 'Should have argon2d signature.');
      assert.equal(undefined, err);
      assert.done();
    });
  },

  test_hash_truthy_argon2d (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, salt, {
      argon2d: 'foo'
    }, (err, hash) => {
      assert.ok(hash, 'Hash should be defined.');
      assert.ok(/\$argon2d\$/.test(hash), 'Should have argon2d signature.');
      assert.equal(undefined, err);
      assert.done();
    });
  },

  test_hash_falsy_argon2d (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, salt, {
      argon2d: ''
    }, (err, hash) => {
      assert.ok(hash, 'Hash should be defined.');
      assert.ok(/\$argon2i\$/.test(hash), 'Should not have argon2d signature.');
      assert.equal(undefined, err);
      assert.done();
    });
  },

  test_hash_long_salt (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, 'somesaltwaytoobig', (err, hash) => {
      assert.ok(err, 'Error should be defined.');
      assert.equal(err.message, 'Invalid salt length, must be 16 bytes.');
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  test_hash_time_cost (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, salt, {
      timeCost: 4
    }, (err, hash) => {
      assert.ok(hash, 'Hash should be defined.');
      assert.ok(/t=4/.test(hash), 'Should have correct time cost.');
      assert.equal(undefined, err);
      assert.done();
    });
  },

  test_hash_invalid_time_cost (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, salt, {
      timeCost: 'foo'
    }, (err, hash) => {
      assert.ok(err, 'Error should be defined.');
      assert.equal(err.message, 'Invalid time cost, must be a number.');
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  test_hash_low_time_cost (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, salt, {
      timeCost: -4294967290
    }, (err, hash) => {
      assert.ok(err, 'Error should be defined.');
      assert.equal(err.message, 'Time cost too low, minimum of 1.');
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  test_hash_high_time_cost (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, salt, {
      timeCost: 4294967297
    }, (err, hash) => {
      assert.ok(err, 'Error should be defined.');
      assert.equal(err.message, 'Time cost too high, maximum of 4294967295.');
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  test_hash_memory_cost (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, salt, {
      memoryCost: 13
    }, (err, hash) => {
      assert.ok(hash, 'Hash should be defined.');
      assert.ok(/m=8192/.test(hash), 'Should have correct memory cost.');
      assert.equal(undefined, err);
      assert.done();
    });
  },

  test_hash_invalid_memory_cost (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, salt, {
      memoryCost: 'foo'
    }, (err, hash) => {
      assert.ok(err, 'Error should be defined.');
      assert.equal(err.message, 'Invalid memory cost, must be a number.');
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  test_hash_low_memory_cost (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, salt, {
      memoryCost: -4294967290
    }, (err, hash) => {
      assert.ok(err, 'Error should be defined.');
      assert.equal(err.message, 'Memory cost too low, minimum of 1.');
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  test_hash_high_memory_cost (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, salt, {
      memoryCost: 32
    }, (err, hash) => {
      assert.ok(err, 'Error should be defined.');
      assert.equal(err.message, 'Memory cost too high, maximum of 31.');
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  test_hash_parallelism (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, salt, {
      parallelism: 2
    }, (err, hash) => {
      assert.ok(hash, 'Hash should be defined.');
      assert.ok(/p=2/.test(hash), 'Should have correct parallelism.');
      assert.equal(undefined, err);
      assert.done();
    });
  },

  test_hash_invalid_parallelism (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, salt, {
      parallelism: 'foo'
    }, (err, hash) => {
      assert.ok(err, 'Error should be defined.');
      assert.equal(err.message, 'Invalid parallelism, must be a number.');
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  test_hash_low_parallelism (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, salt, {
      parallelism: -4294967290
    }, (err, hash) => {
      assert.ok(err, 'Error should be defined.');
      assert.equal(err.message, 'Parallelism too low, minimum of 1.');
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  test_hash_high_parallelism (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, salt, {
      parallelism: 4294967297
    }, (err, hash) => {
      assert.ok(err, 'Error should be defined.');
      assert.equal(err.message, 'Parallelism too high, maximum of 4294967295.');
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  test_hash_all_options (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, salt, {
      timeCost: 4,
      memoryCost: 13,
      parallelism: 2
    }, (err, hash) => {
      assert.ok(hash, 'Hash should be defined.');
      assert.ok(/m=8192,t=4,p=2/.test(hash), 'Should have correct options.');
      assert.equal(undefined, err);
      assert.done();
    });
  },

  test_hash_sync (assert) {
    'use strict';

    assert.expect(1);

    const hash = argon2.hashSync(password, salt);
    assert.equal(hash, '$argon2i$m=4096,t=3,p=1$c29tZXNhbHQAAAAAAAAAAA$FHF/OZ0GJpMRAlBmPTqXxw36Ftp87JllALZPcP9w9gs');
    assert.done();
  },

  test_hash_argon2d_sync (assert) {
    'use strict';

    assert.expect(1);

    const hash = argon2.hashSync(password, salt, {
      argon2d: true
    });
    assert.ok(/\$argon2d\$/.test(hash), 'Should use argon2d signature.');
    assert.done();
  },

  test_hash_truthy_argon2d_sync (assert) {
    'use strict';

    assert.expect(1);

    const hash = argon2.hashSync(password, salt, {
      argon2d: 'foo'
    });
    assert.ok(/\$argon2d\$/.test(hash), 'Should use argon2d signature.');
    assert.done();
  },

  test_hash_falsy_argon2d_sync (assert) {
    'use strict';

    assert.expect(1);

    const hash = argon2.hashSync(password, salt, {
      argon2d: ''
    });
    assert.ok(/\$argon2i\$/.test(hash), 'Should not use argon2d signature.');
    assert.done();
  },

  test_hash_sync_time_cost (assert) {
    'use strict';

    assert.expect(1);

    const hash = argon2.hashSync(password, salt, {
      timeCost: 4
    });
    assert.ok(/t=4/.test(hash), 'Should have correct time cost.');
    assert.done();
  },

  test_hash_sync_invalid_time_cost (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, salt, {
        timeCost: 'foo'
      });
    }, /invalid/i);
    assert.done();
  },

  test_hash_sync_low_time_cost (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, salt, {
        timeCost: -4294967290
      });
    }, /too low/);
    assert.done();
  },

  test_hash_sync_high_time_cost (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, salt, {
        timeCost: 4294967297
      });
    }, /too high/);
    assert.done();
  },

  test_hash_sync_memory_cost (assert) {
    'use strict';

    assert.expect(1);

    const hash = argon2.hashSync(password, salt, {
      memoryCost: 13
    });
    assert.ok(/m=8192/.test(hash), 'Should have correct memory cost.');
    assert.done();
  },

  test_hash_sync_invalid_memory_cost (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, salt, {
        memoryCost: 'foo'
      });
    }, /invalid/i);
    assert.done();
  },

  test_hash_sync_low_memory_cost (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, salt, {
        memoryCost: -4294967290
      });
    }, /too low/);
    assert.done();
  },

  test_hash_sync_high_memory_cost (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, salt, {
        memoryCost: 32
      });
    }, /too high/);
    assert.done();
  },

  test_hash_sync_parallelism (assert) {
    'use strict';

    assert.expect(1);

    const hash = argon2.hashSync(password, salt, {
      parallelism: 2
    });
    assert.ok(/p=2/.test(hash), 'Should have correct parallelism.');
    assert.done();
  },

  test_hash_sync_invalid_parallelism (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, salt, {
        parallelism: 'foo'
      });
    }, /invalid/i);
    assert.done();
  },

  test_hash_sync_low_parallelism (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, salt, {
        parallelism: -4294967290
      });
    }, /too low/);
    assert.done();
  },

  test_hash_sync_high_parallelism (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, salt, {
        parallelism: 4294967297
      });
    }, /too high/);
    assert.done();
  },

  test_hash_sync_all_options (assert) {
    'use strict';

    assert.expect(1);

    const hash = argon2.hashSync(password, salt, {
      timeCost: 4,
      memoryCost: 13,
      parallelism: 2
    });
    assert.ok(/m=8192,t=4,p=2/.test(hash), 'Should have correct options.');
    assert.done();
  },

  test_hash_sync_long_salt (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, 'somesaltwaytoobig');
    });
    assert.done();
  },

  test_generate_salt (assert) {
    'use strict';

    assert.expect(1);

    argon2.generateSalt((err, salt) => {
      assert.ok(salt.length <= 16);
      assert.done();
    });
  },

  test_generate_salt_sync (assert) {
    'use strict';

    assert.expect(1);

    assert.ok(argon2.generateSaltSync().length <= 16);
    assert.done();
  },

  test_verify_ok (assert) {
    'use strict';

    assert.expect(1);

    argon2.verify(argon2.hashSync(password, argon2.generateSaltSync()),
      password, (err) => {
        assert.equal(undefined, err);
        assert.done();
      });
  },

  test_verify_fail (assert) {
    'use strict';

    assert.expect(1);

    argon2.verify(argon2.hashSync(password, argon2.generateSaltSync()),
      'passwolrd', (err) => {
        assert.ok(err, 'Error should be defined.');
        assert.done();
      });
  },

  test_verify_argon2d_ok (assert) {
    'use strict';

    assert.expect(1);

    argon2.hash(password, argon2.generateSaltSync(), {
      argon2d: true
    }, (err, hash) => {
      argon2.verify(hash, password, (err) => {
        assert.equal(undefined, err);
        assert.done();
      });
    });
  },

  test_verify_argon2d_fail (assert) {
    'use strict';

    assert.expect(1);

    argon2.hash(password, argon2.generateSaltSync(), {
      argon2d: true
    }, (err, hash) => {
      argon2.verify(hash, 'passwolrd', (err) => {
        assert.ok(err, 'Error should be defined.');
        assert.done();
      });
    });
  },

  test_verify_sync_ok (assert) {
    'use strict';

    assert.expect(1);

    assert.equal(true, argon2.verifySync(argon2.hashSync(password,
      argon2.generateSaltSync()), password));
    assert.done();
  },

  test_verify_sync_fail (assert) {
    'use strict';

    assert.expect(1);

    assert.equal(false, argon2.verifySync(argon2.hashSync(password,
      argon2.generateSaltSync()), 'passworld'));
    assert.done();
  },

  test_verify_argon2d_sync_ok (assert) {
    'use strict';

    assert.expect(1);

    argon2.hash(password, argon2.generateSaltSync(), {
      argon2d: true
    }, (err, hash) => {
      assert.equal(true, argon2.verifySync(hash, password));
      assert.done();
    });
  },

  test_verify_argon2d_sync_fail (assert) {
    'use strict';

    assert.expect(1);

    argon2.hash(password, argon2.generateSaltSync(), {
      argon2d: true
    }, (err, hash) => {
      assert.equal(false, argon2.verifySync(hash, 'passwolrd'));
      assert.done();
    });
  }
};
