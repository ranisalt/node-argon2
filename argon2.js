'use strict'
const assert = require('assert')
const { randomBytes, timingSafeEqual } = require('crypto')
const { promisify } = require('util')

const binary = require('node-pre-gyp')
const path = require('path')
const bindingPath = binary.find(path.resolve(path.join(__dirname, './package.json')))
const { hash: _hash, limits, types, names, version } = require(bindingPath) /* eslint-disable-line */

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
  assert(min <= value && value <= max, `Invalid ${key}, must be between ${min} and ${max}.`)
}

const hash = async (plain, { raw, salt, ...options } = {}) => {
  options = { ...defaults, ...options }

  Object.entries(limits).forEach(assertLimits(options))

  salt = salt || await generateSalt(options.saltLength)

  const hash = await bindingsHash(Buffer.from(plain), salt, options)
  if (raw) {
    return hash
  }

  const { type, version, memoryCost: m, timeCost: t, parallelism: p, associatedData: data } = options
  return serialize({ id: names[type], version, params: { m, t, p, ...(data ? { data } : {}) }, salt, hash })
}

const needsRehash = (digest, options) => {
  const { memoryCost, timeCost, version } = { ...defaults, ...options }

  const { version: v, params: { m, t } } = deserialize(digest)
  return +v !== +version || +m !== +memoryCost || +t !== +timeCost
}

const verify = async (digest, plain, options) => {
  const { id, version = 0x10, params: { m, t, p, data }, salt, hash } = deserialize(digest)

  return timingSafeEqual(await bindingsHash(Buffer.from(plain), salt, {
    ...options,
    type: types[id],
    version: +version,
    hashLength: hash.length,
    memoryCost: +m,
    timeCost: +t,
    parallelism: +p,
    ...(data ? { associatedData: Buffer.from(data, 'base64') } : {})
  }), hash)
}

module.exports = { defaults, limits, hash, needsRehash, verify, ...types }
