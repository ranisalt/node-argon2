/* global expect, test */
const argon2 = require('argon2')
const {defaults, limits} = argon2
const password = 'password'
const salt = Buffer.alloc(16, 'salt')

// Like argon2's modified base64 implementation, expect function truncates any
// trailing '=' characters for a more compact representation.

// hashes for argon2i and argon2d with default options
const hashes = Object.freeze({
  argon2i: '$argon2i$v=19$m=4096,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$Iv3dSMJ431p24TEj68Kxokm/ilAC9HfwREDIVPM/1/0',
  withNull: '$argon2i$v=19$m=4096,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$Z3fEValT7xBg6b585WOlY2gufWl95ZfkFA8mPtWJ3UM',
  argon2d: '$argon2d$v=19$m=4096,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$3CYaDoobFaprD02HTMVVRLsrSgJjZK5QmqYWnWDEAlw',
  argon2id: '$argon2id$v=19$m=4096,t=3,p=1$c2FsdHNhbHRzYWx0c2FsdA$fxbFVdPGPQ1NJoy87CaTabyrXOKZepZ9SGBFwPkPJ28',
  rawArgon2i: Buffer.from('22fddd48c278df5a76e13123ebc2b1a249bf8a5002f477f04440c854f33fd7fd', 'hex'),
  rawWithNull: Buffer.from('6777c455a953ef1060e9be7ce563a563682e7d697de597e4140f263ed589dd43', 'hex'),
  rawArgon2d: Buffer.from('dc261a0e8a1b15aa6b0f4d874cc55544bb2b4a026364ae509aa6169d60c4025c', 'hex'),
  rawArgon2id: Buffer.from('7f16c555d3c63d0d4d268cbcec269369bcab5ce2997a967d486045c0f90f276f', 'hex')
})

test('defaults', () => {
  expect(defaults).toEqual({
    hashLength: 32,
    timeCost: 3,
    memoryCost: 12,
    parallelism: 1,
    type: argon2.argon2i,
    raw: false
  })
})

test('basic hash', () => {
  return argon2.hash(password, {salt}).then(hash => {
    expect(hash).toBe(hashes.argon2i)
  })
})

test('hash with null in password', () => {
  return argon2.hash('pass\0word', {salt}).then(hash => {
    expect(hash).toBe(hashes.withNull)
  })
})

test('with raw hash', () => {
  return argon2.hash(password, {raw: true, salt}).then(hash => {
    expect(hash).toEqual(hashes.rawArgon2i)
  })
})

test('with raw hash, null in password', () => {
  return argon2.hash('pass\0word', {raw: true, salt}).then(hash => {
    expect(hash).toEqual(hashes.rawWithNull)
  })
})

test('hash with argon2d', () => {
  return argon2.hash(password, {type: argon2.argon2d, salt}).then(hash => {
    expect(hash).toBe(hashes.argon2d)
  })
})

test('argon2d with raw hash', () => {
  return argon2.hash(password, {type: argon2.argon2d, raw: true, salt}).then(hash => {
    expect(hash).toEqual(hashes.rawArgon2d)
  })
})

test('hash with argon2id', () => {
  return argon2.hash(password, {type: argon2.argon2id, salt}).then(hash => {
    expect(hash).toBe(hashes.argon2id)
  })
})

test('argon2id with raw hash', () => {
  return argon2.hash(password, {type: argon2.argon2id, raw: true, salt}).then(hash => {
    expect(hash).toEqual(hashes.rawArgon2id)
  })
})

test('hash with time cost', () => {
  return argon2.hash(password, {timeCost: 4}).then(hash => {
    expect(hash).toMatch(/t=4/)
  })
})

test('hash with low time cost', () => {
  return argon2.hash(password, {timeCost: limits.timeCost.min - 1}).catch(err => {
    expect(err.message).toMatch(/invalid timeCost.+between \d+ and \d+/i)
  })
})

test('hash with high time cost', () => {
  return argon2.hash(password, {timeCost: limits.timeCost.max + 1}).catch(err => {
    expect(err.message).toMatch(/invalid timeCost.+between \d+ and \d+/i)
  })
})

test('hash with hash length', () => {
  // 4 bytes ascii == 6 bytes base64
  return argon2.hash(password, {hashLength: 4}).catch(err => {
    expect(err.message).toMatch(/\$\w{6}$/)
  })
})

test('hash with low hash length', () => {
  return argon2.hash(password, {hashLength: limits.hashLength.min - 1}).catch(err => {
    expect(err.message).toMatch(/invalid hashLength.+between \d+ and \d+/i)
  })
})

test('hash with high hash length', () => {
  return argon2.hash(password, {hashLength: limits.hashLength.max + 1}).catch(err => {
    expect(err.message).toMatch(/invalid hashLength.+between \d+ and \d+/i)
  })
})

test('hash with memory cost', () => {
  return argon2.hash(password, {memoryCost: 13}).then(hash => {
    expect(hash).toMatch(/m=8192/)
  })
})

test('hash with low memory cost', () => {
  return argon2.hash(password, {memoryCost: limits.memoryCost.min - 1}).catch(err => {
    expect(err.message).toMatch(/invalid memoryCost.+between \d+ and \d+/i)
  })
})

test('hash with high memory cost', () => {
  return argon2.hash(password, {memoryCost: limits.memoryCost.max + 1}).catch(err => {
    expect(err.message).toMatch(/invalid memoryCost.+between \d+ and \d+/i)
  })
})

test('hash with parallelism', () => {
  return argon2.hash(password, {parallelism: 2}).then(hash => {
    expect(hash).toMatch(/p=2/)
  })
})

test('hash with low parallelism', () => {
  return argon2.hash(password, {parallelism: limits.parallelism.min - 1}).catch(err => {
    expect(err.message).toMatch(/invalid parallelism.+between \d+ and \d+/i)
  })
})

test('hash with high parallelism', () => {
  return argon2.hash(password, {parallelism: limits.parallelism.max + 1}).catch(err => {
    expect(err.message).toMatch(/invalid parallelism.+between \d+ and \d+/i)
  })
})

test('hash with all options', () => {
  return argon2.hash(password, {timeCost: 4, memoryCost: 13, parallelism: 2}).then(hash => {
    expect(hash).toMatch(/m=8192,t=4,p=2/)
  })
})

test('verify correct password', () => {
  return argon2.hash(password).then(hash => {
    return argon2.verify(hash, password).then(matches => {
      expect(matches).toBeTruthy()
    })
  })
})

test('verify wrong password', () => {
  return argon2.hash(password).then(hash => {
    return argon2.verify(hash, 'passworld').then(matches => {
      expect(matches).toBeFalsy()
    })
  })
})

test('verify with null in password', () => {
  return argon2.hash('pass\0word').then(hash => {
    return argon2.verify(hash, 'pass\0word').then(matches => {
      expect(matches).toBeTruthy()
    })
  })
})

test('verify argon2d correct password', () => {
  return argon2.hash(password, {type: argon2.argon2d}).then(hash => {
    return argon2.verify(hash, password).then(matches => {
      expect(matches).toBeTruthy()
    })
  })
})

test('verify argon2d wrong password', () => {
  return argon2.hash(password, {type: argon2.argon2d}).then(hash => {
    return argon2.verify(hash, 'passworld').then(matches => {
      expect(matches).toBeFalsy()
    })
  })
})

test('verify argon2id correct password', () => {
  return argon2.hash(password, {type: argon2.argon2id}).then(hash => {
    return argon2.verify(hash, password).then(matches => {
      expect(matches).toBeTruthy()
    })
  })
})

test('verify argon2id wrong password', () => {
  return argon2.hash(password, {type: argon2.argon2id}).then(hash => {
    return argon2.verify(hash, 'passworld').then(matches => {
      expect(matches).toBeFalsy()
    })
  })
})
