const assert = require('assert').strict
const argon2 = require('../argon2')
const { argon2i, argon2d, argon2id, defaults, limits } = argon2
const password = 'password'
const salt = Buffer.alloc(16, 'salt')
const associatedData = Buffer.alloc(16, 'ad')

// hashes for argon2i and argon2d with default options
const hashes = Object.freeze({
  argon2i: '$argon2i$v=19$m=4096,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$Iv3dSMJ431p24TEj68Kxokm/ilAC9HfwREDIVPM/1/0',
  withNull: '$argon2i$v=19$m=4096,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$Z3fEValT7xBg6b585WOlY2gufWl95ZfkFA8mPtWJ3UM',
  withAd: '$argon2i$v=19$m=4096,t=3,p=1,data=YWRhZGFkYWRhZGFkYWRhZA$c2FsdHNhbHRzYWx0c2FsdA$1VVB4lnD1cmZaeQIlqyOMQ17g6H9rlC5S/vlYOWuD+M',
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
    assert.deepEqual({
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
    it('hash with argon2i', async () => {
      const hash = await argon2.hash(password, { salt })
      assert.equal(hashes.argon2i, hash)
    })

    it('argon2i with raw hash', async () => {
      const hash = await argon2.hash(password, { raw: true, salt })
      assert(hashes.rawArgon2i.equals(hash))
    })

    it('hash with argon2d', async () => {
      const hash = await argon2.hash(password, { type: argon2d, salt })
      assert.equal(hashes.argon2d, hash)
    })

    it('argon2d with raw hash', async () => {
      const hash = await argon2.hash(password, { type: argon2d, raw: true, salt })
      assert(hashes.rawArgon2d.equals(hash))
    })

    it('hash with argon2id', async () => {
      const hash = await argon2.hash(password, { type: argon2id, salt })
      assert.equal(hashes.argon2id, hash)
    })

    it('argon2id with raw hash', async () => {
      const hash = await argon2.hash(password, { type: argon2id, raw: true, salt })
      assert(hashes.rawArgon2id.equals(hash))
    })

    it('hash with null in password', async () => {
      const hash = await argon2.hash('pass\0word', { salt })
      assert.equal(hashes.withNull, hash)
    })

    it('with raw hash, null in password', async () => {
      const hash = await argon2.hash('pass\0word', { raw: true, salt })
      assert(hashes.rawWithNull.equals(hash))
    })

    it('with associated data', async () => {
      const hash = await argon2.hash(password, { associatedData, salt })
      assert.equal(hashes.withAd, hash)
    })
  })

  describe('set options', () => {
    it('hash with time cost', async () => {
      const hash = await argon2.hash(password, { timeCost: 4 })
      assert(/t=4/.test(hash))
    })

    it('hash with low time cost', async () => {
      try {
        await argon2.hash(password, { timeCost: limits.timeCost.min - 1 })
      } catch (err) {
        assert(/invalid timeCost.+between \d+ and \d+/i.test(err.message))
      }
    })

    it('hash with high time cost', async () => {
      try {
        await argon2.hash(password, { timeCost: limits.timeCost.max + 1 })
      } catch (err) {
        assert(/invalid timeCost.+between \d+ and \d+/i.test(err.message))
      }
    })

    it('hash with hash length', async () => {
      // 4 bytes ascii == 6 bytes base64
      try {
        await argon2.hash(password, { hashLength: 4 })
      } catch (err) {
        assert(/\$\w{6}$/.test(err.message))
      }
    })

    it('hash with low hash length', async () => {
      try {
        await argon2.hash(password, { hashLength: limits.hashLength.min - 1 })
      } catch (err) {
        assert(/invalid hashLength.+between \d+ and \d+/i.test(err.message))
      }
    })

    it('hash with high hash length', async () => {
      try {
        await argon2.hash(password, { hashLength: limits.hashLength.max + 1 })
      } catch (err) {
        assert(/invalid hashLength.+between \d+ and \d+/i.test(err.message))
      }
    })

    it('hash with memory cost', async () => {
      const hash = await argon2.hash(password, { memoryCost: 1 << 13 })
      assert(/m=8192/.test(hash))
    })

    it('hash with low memory cost', async () => {
      try {
        await argon2.hash(password, { memoryCost: limits.memoryCost.min / 2 })
      } catch (err) {
        assert(/invalid memoryCost.+between \d+ and \d+/i.test(err.message))
      }
    })

    it('hash with high memory cost', async () => {
      try {
        await argon2.hash(password, { memoryCost: limits.memoryCost.max * 2 })
      } catch (err) {
        assert(/invalid memoryCost.+between \d+ and \d+/i.test(err.message))
      }
    })

    it('hash with parallelism', async () => {
      const hash = await argon2.hash(password, { parallelism: 2 })
      assert(/p=2/.test(hash))
    })

    it('hash with low parallelism', async () => {
      try {
        await await argon2.hash(password, { parallelism: limits.parallelism.min - 1 })
      } catch (err) {
        assert(/invalid parallelism.+between \d+ and \d+/i.test(err.message))
      }
    })

    it('hash with high parallelism', async () => {
      try {
        await argon2.hash(password, { parallelism: limits.parallelism.max + 1 })
      } catch (err) {
        assert(/invalid parallelism.+between \d+ and \d+/i.test(err.message))
      }
    })

    it('hash with all options', async () => {
      const hash = await argon2.hash(password, { timeCost: 4, memoryCost: 1 << 13, parallelism: 2 })
      assert(/m=8192,t=4,p=2/.test(hash))
    })
  })

  describe('needsRehash', () => {
    it('needs rehash old version', async () => {
      const hash = await argon2.hash(password, { version: 0x10 })
      assert(argon2.needsRehash(hash))
      assert(!argon2.needsRehash(hash, { version: 0x10 }))
    })

    it('needs rehash low memory cost', async () => {
      const hash = await argon2.hash(password, { memoryCost: defaults.memoryCost / 2 })
      assert(argon2.needsRehash(hash))
      assert(!argon2.needsRehash(hash, { memoryCost: defaults.memoryCost / 2 }))
    })

    it('needs rehash low time cost', async () => {
      const hash = await argon2.hash(password, { timeCost: defaults.timeCost - 1 })
      assert(argon2.needsRehash(hash))
      assert(!argon2.needsRehash(hash, { timeCost: defaults.timeCost - 1 }))
    })
  })

  describe('verify', () => {
    it('verify correct password', async () => {
      const hash = await argon2.hash(password)
      assert(await argon2.verify(hash, password))
    })

    it('verify wrong password', async () => {
      const hash = await argon2.hash(password)
      assert(!await argon2.verify(hash, 'passworld'))
    })

    it('verify with null in password', async () => {
      const hash = await argon2.hash('pass\0word')
      assert(await argon2.verify(hash, 'pass\0word'))
    })

    it('verify with associated data', async () => {
      const hash = await argon2.hash(password, { associatedData })
      assert(await argon2.verify(hash, 'password'))
    })

    it('verify argon2d correct password', async () => {
      const hash = await argon2.hash(password, { type: argon2d })
      assert(await argon2.verify(hash, password))
    })

    it('verify argon2d wrong password', async () => {
      const hash = await argon2.hash(password, { type: argon2d })
      assert(!await argon2.verify(hash, 'passworld'))
    })

    it('verify argon2id correct password', async () => {
      const hash = await argon2.hash(password, { type: argon2id })
      assert(await argon2.verify(hash, password))
    })

    it('verify argon2id wrong password', async () => {
      const hash = await argon2.hash(password, { type: argon2id })
      assert(!await argon2.verify(hash, 'passworld'))
    })

    it('verify old hash format', async () => {
      // older hashes did not contain the v (version) parameter
      assert(await argon2.verify(hashes.oldFormat, 'password'))
    })
  })
})
