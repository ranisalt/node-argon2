'use strict'
const { ok } = require('assert').strict
const { randomBytes, timingSafeEqual } = require('crypto')
const { promisify } = require('util')
const { hash: _hash, limits, types, version } = require('bindings')('argon2')
const { deserialize, serialize } = require('@phc/format')

const defaults = Object.freeze({
  hashLength: 32,
  saltLength: 16,
  timeCost: 3,
  memoryCost: 1 << 12,
  parallelism: 1,
  type: types.argon2i,
  version
})

const bindingsHash = promisify(_hash)
const generateSalt = promisify(randomBytes)

const assertLimits = options => ([key, { max, min }]) => {
  const value = options[key]
  ok(min <= value && value <= max, `Invalid ${key}, must be between ${min} and ${max}.`)
}

const hash = async (plain, { raw, salt, ...options } = {}) => {
  options = { ...defaults, ...options }

  Object.entries(limits).forEach(assertLimits(options))

  salt = salt || await generateSalt(options.saltLength)

  const output = await bindingsHash(Buffer.from(plain), salt, options)
  if (raw) {
    return output.hash
  }

  return serialize(output)
}

const needsRehash = (digest, options) => {
  options = { ...defaults, ...options }

  const {
    version, params: { m: memoryCost, t: timeCost }
  } = deserialize(digest)
  return +version !== +options.version ||
    +memoryCost !== +options.memoryCost ||
    +timeCost !== +options.timeCost
}

const verify = async (digest, plain) => {
  const {
    id: type, version = 0x10, params: {
      m: memoryCost, t: timeCost, p: parallelism
    }, salt, hash
  } = deserialize(digest)

  const { hash: expected } = await bindingsHash(Buffer.from(plain), salt, {
    type: module.exports[type],
    version: +version,
    hashLength: hash.length,
    memoryCost: +memoryCost,
    timeCost: +timeCost,
    parallelism: +parallelism
  })
  return timingSafeEqual(expected, hash)
}

module.exports = { defaults, limits, hash, needsRehash, verify, ...types }
