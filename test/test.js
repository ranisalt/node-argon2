const assert = require('assert')
const argon2 = require('../argon2')
const {argon2i, argon2d, argon2id, defaults, limits} = argon2
const password = 'password'
const salt = Buffer.alloc(16, 'salt')

// hashes for argon2i and argon2d with default options
const hashes = Object.freeze({
  argon2i: '$argon2i$v=19$m=4096,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$Iv3dSMJ431p24TEj68Kxokm/ilAC9HfwREDIVPM/1/0',
  withNull: '$argon2i$v=19$m=4096,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$Z3fEValT7xBg6b585WOlY2gufWl95ZfkFA8mPtWJ3UM',
  argon2d: '$argon2d$v=19$m=4096,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$3CYaDoobFaprD02HTMVVRLsrSgJjZK5QmqYWnWDEAlw',
  argon2id: '$argon2id$v=19$m=4096,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$fxbFVdPGPQ1NJoy87CaTabyrXOKZepZ9SGBFwPkPJ28',
  rawArgon2i: Buffer.from('22fddd48c278df5a76e13123ebc2b1a249bf8a5002f477f04440c854f33fd7fd', 'hex'),
  rawWithNull: Buffer.from('6777c455a953ef1060e9be7ce563a563682e7d697de597e4140f263ed589dd43', 'hex'),
  rawArgon2d: Buffer.from('dc261a0e8a1b15aa6b0f4d874cc55544bb2b4a026364ae509aa6169d60c4025c', 'hex'),
  rawArgon2id: Buffer.from('7f16c555d3c63d0d4d268cbcec269369bcab5ce2997a967d486045c0f90f276f', 'hex'),
  oldFormat: '$argon2i$m=4096,t=3,p=1$tbagT6b1YH33niCo9lVzuA$htv/k+OqWk1V9zD9k5DOBi2kcfcZ6Xu3tWmwEPV3/nc'
})

describe('Argon2', () => {
  it('defaults', () => {
    assert.deepStrictEqual({
      hashLength: 32,
      saltLength: 16,
      timeCost: 3,
      memoryCost: 1 << 12,
      parallelism: 1,
      type: argon2i,
      version: 0x13
    }, defaults)
  })

  describe('hash', () => {
    it('hash with argon2i', () => {
      return argon2.hash(password, {salt}).then(hash => {
        assert.strictEqual(hashes.argon2i, hash)
      })
    })

    it('argon2i with raw hash', () => {
      return argon2.hash(password, {raw: true, salt}).then(hash => {
        assert(hashes.rawArgon2i.equals(hash))
      })
    })

    it('hash with argon2d', () => {
      return argon2.hash(password, {type: argon2d, salt}).then(hash => {
        assert.strictEqual(hashes.argon2d, hash)
      })
    })

    it('argon2d with raw hash', () => {
      return argon2.hash(password, {type: argon2d, raw: true, salt}).then(hash => {
        assert(hashes.rawArgon2d.equals(hash))
      })
    })

    it('hash with argon2id', () => {
      return argon2.hash(password, {type: argon2id, salt}).then(hash => {
        assert.strictEqual(hashes.argon2id, hash)
      })
    })

    it('argon2id with raw hash', () => {
      return argon2.hash(password, {type: argon2id, raw: true, salt}).then(hash => {
        assert(hashes.rawArgon2id.equals(hash))
      })
    })

    it('hash with null in password', () => {
      return argon2.hash('pass\0word', {salt}).then(hash => {
        assert.strictEqual(hashes.withNull, hash)
      })
    })


    it('with raw hash, null in password', () => {
      return argon2.hash('pass\0word', {raw: true, salt}).then(hash => {
        assert(hashes.rawWithNull.equals(hash))
      })
    })
  })

  describe('set options', () => {
    it('hash with time cost', () => {
      return argon2.hash(password, {timeCost: 4}).then(hash => {
        assert(/t=4/.test(hash))
      })
    })

    it('hash with low time cost', () => {
      return argon2.hash(password, {timeCost: limits.timeCost.min - 1}).catch(err => {
        assert(/invalid timeCost.+between \d+ and \d+/i.test(err.message))
      })
    })

    it('hash with high time cost', () => {
      return argon2.hash(password, {timeCost: limits.timeCost.max + 1}).catch(err => {
        assert(/invalid timeCost.+between \d+ and \d+/i.test(err.message))
      })
    })

    it('hash with hash length', () => {
      // 4 bytes ascii == 6 bytes base64
      return argon2.hash(password, {hashLength: 4}).catch(err => {
        assert(/\$\w{6}$/.test(err.message))
      })
    })

    it('hash with low hash length', () => {
      return argon2.hash(password, {hashLength: limits.hashLength.min - 1}).catch(err => {
        assert(/invalid hashLength.+between \d+ and \d+/i.test(err.message))
      })
    })

    it('hash with high hash length', () => {
      return argon2.hash(password, {hashLength: limits.hashLength.max + 1}).catch(err => {
        assert(/invalid hashLength.+between \d+ and \d+/i.test(err.message))
      })
    })

    it('hash with memory cost', () => {
      return argon2.hash(password, {memoryCost: 1 << 13}).then(hash => {
        assert(/m=8192/.test(hash))
      })
    })

    it('hash with low memory cost', () => {
      return argon2.hash(password, {memoryCost: limits.memoryCost.min / 2}).catch(err => {
        assert(/invalid memoryCost.+between \d+ and \d+/i.test(err.message))
      })
    })

    it('hash with high memory cost', () => {
      return argon2.hash(password, {memoryCost: limits.memoryCost.max * 2}).catch(err => {
        assert(/invalid memoryCost.+between \d+ and \d+/i.test(err.message))
      })
    })

    it('hash with parallelism', () => {
      return argon2.hash(password, {parallelism: 2}).then(hash => {
        assert(/p=2/.test(hash))
      })
    })

    it('hash with low parallelism', () => {
      return argon2.hash(password, {parallelism: limits.parallelism.min - 1}).catch(err => {
        assert(/invalid parallelism.+between \d+ and \d+/i.test(err.message))
      })
    })

    it('hash with high parallelism', () => {
      return argon2.hash(password, {parallelism: limits.parallelism.max + 1}).catch(err => {
        assert(/invalid parallelism.+between \d+ and \d+/i.test(err.message))
      })
    })

    it('hash with all options', () => {
      return argon2.hash(password, {timeCost: 4, memoryCost: 1 << 13, parallelism: 2}).then(hash => {
        assert(/m=8192,t=4,p=2/.test(hash))
      })
    })
  })

  describe('needsRehash', () => {
    it('needs rehash old version', () => {
      return argon2.hash(password, {version: 0x10}).then(hash => {
        assert(argon2.needsRehash(hash))
        assert(!argon2.needsRehash(hash, {version: 0x10}))
      })
    })

    it('needs rehash low memory cost', () => {
      return argon2.hash(password, {memoryCost: defaults.memoryCost / 2}).then(hash => {
        assert(argon2.needsRehash(hash))
        assert(!argon2.needsRehash(hash, {memoryCost: defaults.memoryCost / 2}))
      })
    })

    it('needs rehash low time cost', () => {
      return argon2.hash(password, {timeCost: defaults.timeCost - 1}).then(hash => {
        assert(argon2.needsRehash(hash))
        assert(!argon2.needsRehash(hash, {timeCost: defaults.timeCost - 1}))
      })
    })
  })

  describe('verify', () => {
    it('verify correct password', () => {
      return argon2.hash(password).then(hash => {
        return argon2.verify(hash, password).then(matches => {
          assert(matches)
        })
      })
    })

    it('verify wrong password', () => {
      return argon2.hash(password).then(hash => {
        return argon2.verify(hash, 'passworld').then(matches => {
          assert(!matches)
        })
      })
    })

    it('verify with null in password', () => {
      return argon2.hash('pass\0word').then(hash => {
        return argon2.verify(hash, 'pass\0word').then(matches => {
          assert(matches)
        })
      })
    })

    it('verify argon2d correct password', () => {
      return argon2.hash(password, {type: argon2d}).then(hash => {
        return argon2.verify(hash, password).then(matches => {
          assert(matches)
        })
      })
    })

    it('verify argon2d wrong password', () => {
      return argon2.hash(password, {type: argon2d}).then(hash => {
        return argon2.verify(hash, 'passworld').then(matches => {
          assert(!matches)
        })
      })
    })

    it('verify argon2id correct password', () => {
      return argon2.hash(password, {type: argon2id}).then(hash => {
        return argon2.verify(hash, password).then(matches => {
          assert(matches)
        })
      })
    })

    it('verify argon2id wrong password', () => {
      return argon2.hash(password, {type: argon2id}).then(hash => {
        return argon2.verify(hash, 'passworld').then(matches => {
          assert(!matches)
        })
      })
    })

    it('verify old hash format', () => {
      // older hashes did not contain the v (version) parameter
      return argon2.verify(hashes.oldFormat, 'password').then(matches => {
        assert(matches)
      })
    })
  })
})
