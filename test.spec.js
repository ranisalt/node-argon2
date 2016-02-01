const argon2 = process.env.COVERAGE
  ? require('./index-cov')
  : require('./index');

const password = 'password';
const salt = new Buffer(16);
salt.fill(0).write('somesalt');

const limits = argon2.limits;

module.exports = {
  testDefaults  (assert) {
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

  testHashCallback (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, salt, (err, hash) => {
      assert.ok(hash, 'Hash should be defined.');
      assert.equal(hash, '$argon2i$m=4096,t=3,p=1$c29tZXNhbHQAAAAAAAAAAA$FHF/OZ0GJpMRAlBmPTqXxw36Ftp87JllALZPcP9w9gs');
      assert.equal(undefined, err);
      assert.done();
    });
  },

  testHashPromise (assert) {
    'use strict';

    assert.expect(1);

    argon2.hash(password, salt).then((hash) => {
      assert.equal(hash, '$argon2i$m=4096,t=3,p=1$c29tZXNhbHQAAAAAAAAAAA$FHF/OZ0GJpMRAlBmPTqXxw36Ftp87JllALZPcP9w9gs');
      assert.done();
    });
  },

  testHashArgon2d (assert) {
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

  testHashTruthyArgon2d (assert) {
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

  testHashFalsyArgon2d (assert) {
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

  testHashLongSalt (assert) {
    'use strict';

    assert.expect(3);

    argon2.hash(password, 'somesaltwaytoobig', (err, hash) => {
      assert.ok(err, 'Error should be defined.');
      assert.equal(err.message, 'Invalid salt length, must be 16 bytes.');
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  testHashPromiseFail (assert) {
    'use strict';

    assert.expect(1);

    argon2.hash(password, 'somesaltwaytoobig').catch((err) => {
      assert.ok(err, 'Error should be defined.');
      assert.done();
    });
  },

  testHashTimeCost (assert) {
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

  testHashInvalidTimeCost (assert) {
    'use strict';

    assert.expect(2);

    argon2.hash(password, salt, {
      timeCost: 'foo'
    }, (err, hash) => {
      assert.ok(/invalid time cost, must be an integer/i.test(err.message));
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  testHashLowTimeCost (assert) {
    'use strict';

    assert.expect(2);

    argon2.hash(password, salt, {
      timeCost: limits.timeCost.min - 1
    }, (err, hash) => {
      assert.ok(/invalid time cost.+between \d+ and \d+/i.test(err.message));
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  testHashHighTimeCost (assert) {
    'use strict';

    assert.expect(2);

    argon2.hash(password, salt, {
      timeCost: limits.timeCost.max + 1
    }, (err, hash) => {
      assert.ok(/invalid time cost.+between \d+ and \d+/i.test(err.message));
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  testHashMemoryCost (assert) {
    'use strict';

    assert.expect(2);

    argon2.hash(password, salt, {
      memoryCost: 13
    }, (err, hash) => {
      assert.ok(/m=8192/.test(hash), 'Should have correct memory cost.');
      assert.equal(undefined, err);
      assert.done();
    });
  },

  testHashInvalidMemoryCost (assert) {
    'use strict';

    assert.expect(2);

    argon2.hash(password, salt, {
      memoryCost: 'foo'
    }, (err, hash) => {
      assert.ok(/invalid memory cost, must be an integer/i.test(err.message));
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  testHashLowMemoryCost (assert) {
    'use strict';

    assert.expect(2);

    argon2.hash(password, salt, {
      memoryCost: limits.memoryCost.min - 1
    }, (err, hash) => {
      assert.ok(/invalid memory cost.+between \d+ and \d+/i.test(err.message));
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  testHashHighMemoryCost (assert) {
    'use strict';

    assert.expect(2);

    argon2.hash(password, salt, {
      memoryCost: limits.memoryCost.max + 1
    }, (err, hash) => {
      assert.ok(/invalid memory cost.+between \d+ and \d+/i.test(err.message));
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  testHashParallelism (assert) {
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

  testHashInvalidParallelism (assert) {
    'use strict';

    assert.expect(2);

    argon2.hash(password, salt, {
      parallelism: 'foo'
    }, (err, hash) => {
      assert.ok(/invalid parallelism, must be an integer/i.test(err.message));
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  testHashLowParallelism (assert) {
    'use strict';

    assert.expect(2);

    argon2.hash(password, salt, {
      parallelism: limits.parallelism.min - 1
    }, (err, hash) => {
      assert.ok(/invalid parallelism.+between \d+ and \d+/i.test(err.message));
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  testHashHighParallelism (assert) {
    'use strict';

    assert.expect(2);

    argon2.hash(password, salt, {
      parallelism: limits.parallelism.max + 1
    }, (err, hash) => {
      assert.ok(/invalid parallelism.+between \d+ and \d+/i.test(err.message));
      assert.equal(undefined, hash);
      assert.done();
    });
  },

  testHashAllOptions (assert) {
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

  testHashOptionsPromise (assert) {
    'use strict';

    assert.expect(2);

    argon2.hash(password, salt, {
      timeCost: 4,
      memoryCost: 13,
      parallelism: 2
    }).then((hash) => {
      assert.ok(hash, 'Hash should be defined.');
      assert.ok(/m=8192,t=4,p=2/.test(hash), 'Should have correct options.');
      assert.done();
    });
  },

  testHashSync (assert) {
    'use strict';

    assert.expect(1);

    const hash = argon2.hashSync(password, salt);
    assert.equal(hash, '$argon2i$m=4096,t=3,p=1$c29tZXNhbHQAAAAAAAAAAA$FHF/OZ0GJpMRAlBmPTqXxw36Ftp87JllALZPcP9w9gs');
    assert.done();
  },

  testHashArgon2dSync (assert) {
    'use strict';

    assert.expect(1);

    const hash = argon2.hashSync(password, salt, {
      argon2d: true
    });
    assert.ok(/\$argon2d\$/.test(hash), 'Should use argon2d signature.');
    assert.done();
  },

  testHashTruthyArgon2dSync (assert) {
    'use strict';

    assert.expect(1);

    const hash = argon2.hashSync(password, salt, {
      argon2d: 'foo'
    });
    assert.ok(/\$argon2d\$/.test(hash), 'Should use argon2d signature.');
    assert.done();
  },

  testHashFalsyArgon2dSync (assert) {
    'use strict';

    assert.expect(1);

    const hash = argon2.hashSync(password, salt, {
      argon2d: ''
    });
    assert.ok(/\$argon2i\$/.test(hash), 'Should not use argon2d signature.');
    assert.done();
  },

  testHashSyncTimeCost (assert) {
    'use strict';

    assert.expect(1);

    const hash = argon2.hashSync(password, salt, {
      timeCost: 4
    });
    assert.ok(/t=4/.test(hash), 'Should have correct time cost.');
    assert.done();
  },

  testHashSyncInvalidTimeCost (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, salt, {
        timeCost: 'foo'
      });
    }, /invalid time cost.+must be an integer/i);
    assert.done();
  },

  testHashSyncLowTimeCost (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, salt, {
        timeCost: limits.timeCost.min - 1
      });
    }, /invalid time cost.+between \d+ and \d+/i);
    assert.done();
  },

  testHashSyncHighTimeCost (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, salt, {
        timeCost: limits.timeCost.max + 1
      });
    }, /invalid time cost.+between \d+ and \d+/i);
    assert.done();
  },

  testHashSyncMemoryCost (assert) {
    'use strict';

    assert.expect(1);

    const hash = argon2.hashSync(password, salt, {
      memoryCost: 13
    });
    assert.ok(/m=8192/.test(hash), 'Should have correct memory cost.');
    assert.done();
  },

  testHashSyncInvalidMemoryCost (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, salt, {
        memoryCost: 'foo'
      });
    }, /invalid memory cost, must be an integer/i);
    assert.done();
  },

  testHashSyncLowMemoryCost (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, salt, {
        memoryCost: limits.memoryCost.min - 1
      });
    }, /invalid memory cost.+between \d+ and \d+/i);
    assert.done();
  },

  testHashSyncHighMemoryCost (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, salt, {
        memoryCost: limits.memoryCost.max + 1
      });
    }, /invalid memory cost.+between \d+ and \d+/i);
    assert.done();
  },

  testHashSyncParallelism (assert) {
    'use strict';

    assert.expect(1);

    const hash = argon2.hashSync(password, salt, {
      parallelism: 2
    });
    assert.ok(/p=2/.test(hash), 'Should have correct parallelism.');
    assert.done();
  },

  testHashSyncInvalidParallelism (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, salt, {
        parallelism: 'foo'
      });
    }, /invalid parallelism, must be an integer/i);
    assert.done();
  },

  testHashSyncLowParallelism (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, salt, {
        parallelism: limits.parallelism.min - 1
      });
    }, /invalid parallelism.+between \d+ and \d+/i);
    assert.done();
  },

  testHashSyncHighParallelism (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, salt, {
        parallelism: limits.parallelism.max + 1
      });
    }, /invalid parallelism.+between \d+ and \d+/i);
    assert.done();
  },

  testHashSyncAllOptions (assert) {
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

  testHashSyncLongSalt (assert) {
    'use strict';

    assert.expect(1);

    assert.throws(() => {
      argon2.hashSync(password, 'somesaltwaytoobig');
    });
    assert.done();
  },

  testGenerateSaltCallback (assert) {
    'use strict';

    assert.expect(2);

    argon2.generateSalt((err, salt) => {
      assert.equal(undefined, err);
      assert.ok(salt.length <= 16);
      assert.done();
    });
  },

  testGenerateSaltPromise (assert) {
    'use strict';

    assert.expect(1);

    argon2.generateSalt().then((salt) => {
      assert.ok(salt.length <= 16);
      assert.done();
    });
  },

  testGenerateSaltSync (assert) {
    'use strict';

    assert.expect(1);

    assert.ok(argon2.generateSaltSync().length <= 16);
    assert.done();
  },

  testVerifyOkCallback (assert) {
    'use strict';

    assert.expect(1);

    argon2.generateSalt().then((salt) => {
      argon2.hash(password, salt, {
        argon2d: true
      }).then((hash) => {
        argon2.verify(hash, password, (err) => {
          assert.equal(undefined, err);
          assert.done();
        });
      });
    });
  },

  testVerifyOkPromise (assert) {
    'use strict';

    assert.expect(0);

    argon2.generateSalt().then((salt) => {
      argon2.hash(password, salt).then((hash) => {
        argon2.verify(hash, password).then(assert.done);
      });
    });
  },

  testVerifyFailCallback (assert) {
    'use strict';

    assert.expect(1);

    argon2.generateSalt().then((salt) => {
      argon2.hash(password, salt, {
        argon2d: true
      }).then((hash) => {
        argon2.verify(hash, 'passwolrd', (err) => {
          assert.ok(err, 'Error should be defined.');
          assert.done();
        });
      });
    });
  },

  testVerifyFailPromise (assert) {
    'use strict';

    assert.expect(1);

    argon2.generateSalt().then((salt) => {
      argon2.hash(password, salt).then((hash) => {
        argon2.verify(hash, 'passworld').catch((err) => {
          assert.ok(err, 'Error should be defined');
          assert.done();
        });
      });
    });
  },

  testVerifyArgon2dOk (assert) {
    'use strict';

    assert.expect(0);

    argon2.generateSalt().then((salt) => {
      argon2.hash(password, salt, {
        argon2d: true
      }).then((hash) => {
        argon2.verify(hash, password).then(assert.done);
      });
    });
  },

  testVerifyArgon2dFail (assert) {
    'use strict';

    assert.expect(1);

    argon2.generateSalt().then((salt) => {
      argon2.hash(password, salt, {
        argon2d: true
      }).then((hash) => {
        argon2.verify(hash, 'passwolrd').catch((err) => {
          assert.ok(err, 'Error should be defined');
          assert.done();
        });
      });
    });
  },

  testVerifySyncOk (assert) {
    'use strict';

    assert.expect(1);

    argon2.generateSalt().then((salt) => {
      argon2.hash(password, salt).then((hash) => {
        assert.equal(true, argon2.verifySync(hash, password));
        assert.done();
      });
    });
  },

  testVerifySyncFail (assert) {
    'use strict';

    assert.expect(1);

    argon2.generateSalt().then((salt) => {
      argon2.hash(password, salt).then((hash) => {
        assert.equal(false, argon2.verifySync(hash, 'passworld'));
        assert.done();
      });
    });
  },

  testVerifyArgon2dSyncOk (assert) {
    'use strict';

    assert.expect(1);

    argon2.generateSalt().then((salt) => {
      argon2.hash(password, salt, {
        argon2d: true
      }).then((hash) => {
        assert.equal(true, argon2.verifySync(hash, password));
        assert.done();
      });
    });
  },

  testVerifyArgon2dSyncFail (assert) {
    'use strict';

    assert.expect(1);

    argon2.generateSalt().then((salt) => {
      argon2.hash(password, salt, {
        argon2d: true
      }).then((hash) => {
        assert.equal(false, argon2.verifySync(hash, 'passwolrd'));
        assert.done();
      });
    });
  }
};
