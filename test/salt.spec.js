const t = require('tap')
const argon2 = require('../index')

t.test('async generate salt with default length', t => {
  'use strict'

  t.plan(1)

  return argon2.generateSalt().then(salt => {
    t.equal(salt.length, 16)
  })
}).catch(t.threw)

t.test('async generate salt with specified length', t => {
  'use strict'

  t.plan(1)

  return argon2.generateSalt(32).then(salt => {
    t.equal(salt.length, 32)
  })
}).catch(t.threw)
