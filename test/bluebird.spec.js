const Bluebird = require('bluebird')
const t = require('tap')
const argon2 = require('../')

argon2.Promise = Bluebird

const password = 'password'
const salt = new Buffer('somesalt')

const hashes = Object.freeze({
  argon2i: '$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$iWh06vD8Fy27wf9npn6FXWiCX4K6pW6Ue1Bnzz07Z8A',
  argon2d: '$argon2d$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$2+JCoQtY/2x5F0VB9pEVP3xBNguWP1T25Ui0PtZuk8o'
})

t.test('bluebird hash', t => {
  'use strict'

  t.plan(1)
  return argon2.hash(password, salt).then(hash => {
    t.equal(hash, hashes.argon2i)
  })
})

t.test('bluebird generate salt', t => {
  'use strict'

  t.plan(1)

  return argon2.generateSalt().then(salt => {
    t.equal(salt.length, 16)
  })
}).catch(t.threw)

t.test('bluebird verify', t => {
  'use strict'

  t.plan(1)

  return argon2.generateSalt().then(salt => {
    return argon2.hash(password, salt).then(hash => {
      return argon2.verify(hash, password).then(result => {
        t.true(result)
      })
    })
  })
}).catch(t.threw)
