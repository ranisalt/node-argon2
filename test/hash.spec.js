const t = require('tap')
const argon2 = require('../index')

const password = 'password'
const salt = new Buffer('somesalt')
const saltWithNull = new Buffer('\0abcdefghijklmno')

// Like argon2's modified base64 implementation, this function truncates any
// trailing '=' characters for a more compact representation.
const truncatedBase64 = buffer => buffer.toString('base64').replace(/=*$/, '')

// hashes for argon2i and argon2d with default options
const hashes = Object.freeze({
  argon2i: '$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$iWh06vD8Fy27wf9npn6FXWiCX4K6pW6Ue1Bnzz07Z8A',
  argon2d: '$argon2d$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$2+JCoQtY/2x5F0VB9pEVP3xBNguWP1T25Ui0PtZuk8o'
})

const limits = argon2.limits

t.test('defaults', t => {
  'use strict'

  t.equivalent(argon2.defaults, {
    timeCost: 3,
    memoryCost: 12,
    parallelism: 1,
    argon2d: false
  })
  t.end()
})

t.test('basic hash', t => {
  'use strict'

  t.plan(1)

  return argon2.hash(password, salt).then(hash => {
    t.equal(hash, hashes.argon2i)
  })
}).catch(t.threw)

t.test('hash with null in password', t => {
  'use strict'

  t.plan(1)

  return argon2.hash('pass\0word', salt).then(hash => {
    t.equal(hash, '$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$gk27gZBfGSSQTGxrg0xP9BjOw1pY1QMEdLcNe+t6N8Q')
  })
}).catch(t.threw)

t.test('hash with null in salt', t => {
  'use strict'

  t.plan(1)

  return argon2.hash(password, saltWithNull).then(hash => {
    const paramsLen = '$argon2i$v=19$m=4096,t=3,p=1'.length
    const saltBase64 = hash.substring(paramsLen, paramsLen + 24)
    t.equal(saltBase64, `\$${truncatedBase64(saltWithNull)}\$`)
  })
}).catch(t.threw)

t.test('hash with longer salt', t => {
  'use strict'

  t.plan(2)

  /* intentionally using a length that is not multiple of 3 */
  return argon2.generateSalt(500).then(salt => {
    return argon2.hash('password', salt).then(hash => {
      t.match(hash, /.*\$.{667}\$/, 'Hash should use the entire salt')
      return argon2.verify(hash, 'password').then(t.ok)
    })
  })
}).catch(t.threw)

t.test('hash with argon2d', t => {
  'use strict'

  t.plan(2)

  return argon2.hash(password, salt, {
    argon2d: true
  }).then(hash => {
    t.match(hash, /\$argon2d\$/, 'Should have argon2d signature.')
    t.equal(hash, hashes.argon2d)
  })
}).catch(t.threw)

t.test('hash with truthy argon2d', t => {
  'use strict'

  t.plan(1)

  return argon2.hash(password, salt, {
    argon2d: 'foo'
  }).then(hash => {
    t.match(hash, /\$argon2d\$/, 'Should have argon2d signature.')
  })
}).catch(t.threw)

t.test('hash with falsy argon2d', t => {
  'use strict'

  t.plan(1)

  return argon2.hash(password, salt, {
    argon2d: ''
  }).then(hash => {
    t.notMatch(hash, /\$argon2d\$/, 'Should not have argon2d signature.')
  })
}).catch(t.threw)

t.test('hash with invalid salt', t => {
  'use strict'

  t.plan(1)

  return argon2.hash(password, 'stringsalt').catch(err => {
    t.match(err.message, /invalid salt.+must be a buffer/i)
  })
})

t.test('hash with short salt', t => {
  'use strict'

  t.plan(1)

  return argon2.hash(password, salt.slice(0, 7)).catch(err => {
    t.match(err.message, /invalid salt.+with 8 or more bytes/i)
  })
})

t.test('hash with time cost', t => {
  'use strict'

  t.plan(1)

  return argon2.hash(password, salt, {
    timeCost: 4
  }).then(hash => {
    t.match(hash, /t=4/, 'Should have correct time cost.')
  })
}).catch(t.threw)

t.test('hash with invalid time cost', t => {
  'use strict'

  t.plan(1)

  return argon2.hash(password, salt, {
    timeCost: 'foo'
  }).catch(err => {
    t.match(err.message, /invalid timeCost.+must be an integer/i)
  })
})

t.test('hash with low time cost', t => {
  'use strict'

  t.plan(1)

  return argon2.hash(password, salt, {
    timeCost: limits.timeCost.min - 1
  }).catch(err => {
    t.match(err.message, /invalid timeCost.+between \d+ and \d+/i)
  })
})

t.test('hash with high time cost', t => {
  'use strict'

  t.plan(1)

  return argon2.hash(password, salt, {
    timeCost: limits.timeCost.max + 1
  }).catch(err => {
    t.match(err.message, /invalid timeCost.+between \d+ and \d+/i)
  })
})

t.test('hash with memory cost', t => {
  'use strict'

  t.plan(1)

  return argon2.hash(password, salt, {
    memoryCost: 13
  }).then(hash => {
    t.match(hash, /m=8192/, 'Should have correct memory cost.')
  })
}).catch(t.threw)

t.test('hash with invalid time cost', t => {
  'use strict'

  t.plan(1)

  return argon2.hash(password, salt, {
    memoryCost: 'foo'
  }).catch(err => {
    t.match(err.message, /invalid memoryCost.+must be an integer/i)
  })
})

t.test('hash with low time cost', t => {
  'use strict'

  t.plan(1)

  return argon2.hash(password, salt, {
    memoryCost: limits.memoryCost.min - 1
  }).catch(err => {
    t.match(err.message, /invalid memoryCost.+between \d+ and \d+/i)
  })
})

t.test('hash with high time cost', t => {
  'use strict'

  t.plan(1)

  return argon2.hash(password, salt, {
    memoryCost: limits.memoryCost.max + 1
  }).catch(err => {
    t.match(err.message, /invalid memoryCost.+between \d+ and \d+/i)
  })
})

t.test('hash with parallelism', t => {
  'use strict'

  t.plan(1)

  return argon2.hash(password, salt, {
    parallelism: 2
  }).then(hash => {
    t.match(hash, /p=2/, 'Should have correct parallelism.')
  })
}).catch(t.threw)

t.test('hash with invalid parallelism', t => {
  'use strict'

  t.plan(1)

  return argon2.hash(password, salt, {
    parallelism: 'foo'
  }).catch(err => {
    t.match(err.message, /invalid parallelism, must be an integer/i)
  })
})

t.test('hash with low parallelism', t => {
  'use strict'

  t.plan(1)

  return argon2.hash(password, salt, {
    parallelism: limits.parallelism.min - 1
  }).catch(err => {
    t.match(err.message, /invalid parallelism.+between \d+ and \d+/i)
  })
})

t.test('hash with high parallelism', t => {
  'use strict'

  t.plan(1)

  return argon2.hash(password, salt, {
    parallelism: limits.parallelism.max + 1
  }).catch(err => {
    t.match(err.message, /invalid parallelism.+between \d+ and \d+/i)
  })
})

t.test('hash with all options', t => {
  'use strict'

  t.plan(1)

  return argon2.hash(password, salt, {
    timeCost: 4,
    memoryCost: 13,
    parallelism: 2
  }).then(hash => {
    t.match(hash, /m=8192,t=4,p=2/, 'Should have correct options.')
  })
}).catch(t.threw)
