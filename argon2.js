'use strict'
const { randomBytes, timingSafeEqual } = require('crypto')
const { promisify } = require('util')
const bindings = require('bindings')('argon2')
const phc = require('@phc/format')

const limits = Object.freeze(bindings.limits)
const types = Object.freeze(bindings.types)

const defaults = Object.freeze({
  hashLength: 32,
  saltLength: 16,
  timeCost: 3,
  memoryCost: 1 << 12,
  parallelism: 1,
  type: types.argon2i,
  version: bindings.version
})

const bindingsHash = promisify(bindings.hash)
const generateSalt = promisify(randomBytes)

const hash = async (plain, { raw, salt, ...options } = {}) => {
  options = { ...defaults, ...options }

  for (const [key, { max, min }] of Object.entries(limits)) {
    const value = options[key]
    if (value > max || value < min) {
      throw new Error(`Invalid ${key}, must be between ${min} and ${max}.`)
    }
  }

  salt = salt || await generateSalt(options.saltLength)

  const output = await bindingsHash(Buffer.from(plain), salt, options)
  if (raw) {
    return output.hash
  }

  return phc.serialize(output)
}

const needsRehash = (digest, options) => {
  options = { ...defaults, ...options }

  const {
    version, params: { m: memoryCost, t: timeCost }
  } = phc.deserialize(digest)
  return +version !== +options.version ||
    +memoryCost !== +options.memoryCost ||
    +timeCost !== +options.timeCost
}

const verify = async (digest, plain) => {
  const {
    id: type, version = 0x10, params: {
      m: memoryCost, t: timeCost, p: parallelism
    }, salt, hash
  } = phc.deserialize(digest)

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
