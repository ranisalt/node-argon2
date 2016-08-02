import test from 'ava'
import argon2, {defaults, limits} from './'

const password = 'password'
const salt = new Buffer('somesalt')
const saltWithNull = new Buffer('\0abcdefghijklmno')

// Like argon2's modified base64 implementation, this function truncates any
// trailing '=' characters for a more compact representation.
const truncatedBase64 = buffer => buffer.toString('base64').replace(/=*$/, '')

// hashes for argon2i and argon2d with default options
const hashes = Object.freeze({
  argon2i: '$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$iWh06vD8Fy27wf9npn6FXWiCX4K6pW6Ue1Bnzz07Z8A',
  argon2d: '$argon2d$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$2+JCoQtY/2x5F0VB9pEVP3xBNguWP1T25Ui0PtZuk8o',
  withNull: '$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$gk27gZBfGSSQTGxrg0xP9BjOw1pY1QMEdLcNe+t6N8Q'
})

test('defaults', t => {
  t.deepEqual(defaults, {
    timeCost: 3,
    memoryCost: 12,
    parallelism: 1,
    argon2d: false
  })
})

test('basic hash', async t => {
  t.is(await argon2.hash(password, salt), hashes.argon2i)
})

test('hash with null in password', async t => {
  t.is(await argon2.hash('pass\0word', salt), hashes.withNull)
})

test('hash with null in salt', async t => {
  const hash = await argon2.hash(password, saltWithNull)
  const paramsLen = '$argon2i$v=19$m=4096,t=3,p=1$'.length
  t.is(hash.substring(paramsLen, paramsLen + 22), truncatedBase64(saltWithNull))
})

test('hash with longer salt', async t => {
  /* Intentionally using a length that is not multiple of 3 */
  const hash = await argon2.hash('password', await argon2.generateSalt(500))
  t.regex(hash, /.*\$.{667}\$/)
  t.true(await argon2.verify(hash, 'password'))
})

test('hash with argon2d', async t => {
  t.is(await argon2.hash(password, salt, {
    argon2d: true
  }), hashes.argon2d)
})

test('hash with truthy argon2d', async t => {
  t.regex(await argon2.hash(password, salt, {
    argon2d: 'foo'
  }), /\$argon2d\$/)
})

test('hash with falsy argon2d', async t => {
  t.regex(await argon2.hash(password, salt, {
    argon2d: ''
  }), /\$argon2[^d]\$/)
})

test('hash with invalid salt', async t => {
  t.throws(argon2.hash(password, 'stringsalt'), /invalid salt.+must be a buffer/i)
})

test('hash with short salt', async t => {
  t.throws(argon2.hash(password, salt.slice(0, 7)), /invalid salt.+with 8 or more bytes/i)
})

test('hash with time cost', async t => {
  t.regex(await argon2.hash(password, salt, {
    timeCost: 4
  }), /t=4/)
})

test('hash with invalid time cost', async t => {
  t.throws(argon2.hash(password, salt, {
    timeCost: 'foo'
  }), /invalid timeCost.+must be an integer/i)
})

test('hash with low time cost', async t => {
  t.throws(argon2.hash(password, salt, {
    timeCost: limits.timeCost.min - 1
  }), /invalid timeCost.+between \d+ and \d+/i)
})

test('hash with high time cost', async t => {
  t.throws(argon2.hash(password, salt, {
    timeCost: limits.timeCost.max + 1
  }), /invalid timeCost.+between \d+ and \d+/i)
})

test('hash with memory cost', async t => {
  t.regex(await argon2.hash(password, salt, {
    memoryCost: 13
  }), /m=8192/)
})

test('hash with invalid memory cost', async t => {
  t.throws(argon2.hash(password, salt, {
    memoryCost: 'foo'
  }), /invalid memoryCost.+must be an integer/i)
})

test('hash with low memory cost', async t => {
  t.throws(argon2.hash(password, salt, {
    memoryCost: limits.memoryCost.min - 1
  }), /invalid memoryCost.+between \d+ and \d+/i)
})

test('hash with high memory cost', async t => {
  t.throws(argon2.hash(password, salt, {
    memoryCost: limits.memoryCost.max + 1
  }), /invalid memoryCost.+between \d+ and \d+/i)
})

test('hash with parallelism', async t => {
  t.regex(await argon2.hash(password, salt, {
    parallelism: 2
  }), /p=2/)
})

test('hash with invalid parallelism', async t => {
  t.throws(argon2.hash(password, salt, {
    parallelism: 'foo'
  }), /invalid parallelism, must be an integer/i)
})

test('hash with low parallelism', async t => {
  t.throws(argon2.hash(password, salt, {
    parallelism: limits.parallelism.min - 1
  }), /invalid parallelism.+between \d+ and \d+/i)
})

test('hash with high parallelism', async t => {
  t.throws(argon2.hash(password, salt, {
    parallelism: limits.parallelism.max + 1
  }), /invalid parallelism.+between \d+ and \d+/i)
})

test('hash with all options', async t => {
  t.regex(await argon2.hash(password, salt, {
    timeCost: 4,
    memoryCost: 13,
    parallelism: 2
  }), /m=8192,t=4,p=2/)
})

test('async generate salt with default length', async t => {
  t.is((await argon2.generateSalt()).length, 16)
})

test('async generate salt with specified length', async t => {
  t.is((await argon2.generateSalt(32)).length, 32)
})

test('verify correct password', async t => {
  t.true(await argon2.verify(await argon2.hash(password, await argon2.generateSalt()), password))
})

test('verify wrong password', async t => {
  t.false(await argon2.verify(await argon2.hash(password, await argon2.generateSalt()), 'passworld'))
})

test('verify invalid hash', async t => {
  const hash = await argon2.hash(password, await argon2.generateSalt())
  /* Cut just a piece of the hash making it invalid */
  t.throws(argon2.verify(hash.slice(8), password), /invalid hash.+generated by argon2/i)
})

test('verify with null in password', async t => {
  t.true(await argon2.verify(await argon2.hash('pass\0word', await argon2.generateSalt()), 'pass\0word'))
})

test('verify argon2d correct password', async t => {
  t.true(await argon2.verify(await argon2.hash(password, await argon2.generateSalt(), {
    argon2d: true
  }), password))
})

test('verify argon2d wrong password', async t => {
  t.false(await argon2.verify(await argon2.hash(password, await argon2.generateSalt(), {
    argon2d: true
  }), 'passworld'))
})

test('js promise + setInterval', async t => {
  const timer = setInterval(() => {
    /* istanbul ignore next */
    t.fail('Interval expired first')
  }, 5e3)

  await argon2.hash(password, salt)
  clearInterval(timer)
})

test('js promise + setTimeout', async t => {
  const timer = setTimeout(() => {
    /* istanbul ignore next */
    t.fail('Timeout expired first')
  }, 5e3)

  await argon2.hash(password, salt)
  clearTimeout(timer)
})
