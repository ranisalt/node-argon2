'use strict'
const crypto = require('crypto')
const bindings = require('bindings')('argon2')
const Promise = require('any-promise')
const phc = require('@phc/format')

const limits = Object.freeze(bindings.limits)
const types = Object.freeze(bindings.types)
const version = bindings.version

const defaults = Object.freeze({
  hashLength: 32,
  timeCost: 3,
  memoryCost: 2 ** 12,
  parallelism: 1,
  type: types.argon2i,
  raw: false,
  version,
})

const type2string = []

const rightPad = encoded => encoded + '='.repeat(encoded.length % 4)
const rightTrim = encoded => encoded.replace(/=+$/, '')

const hash = (plain, options) => {
  options = Object.assign({}, defaults, options)

  return new Promise((resolve, reject) => {
    for (let key of Object.keys(limits)) {
      const {max, min} = limits[key]
      const value = options[key]
      if (value > max || value < min) {
        reject(new Error(`Invalid ${key}, must be between ${min} and ${max}.`))
      }
    }

    // TODO: after transition time, drop this check
    if (options.memoryCost < 32) {
      const exp = options.memoryCost
      process.emitWarning('[argon2] deprecated usage of options.memoryCost', {
        detail: 'The argon2 package now uses value of memory cost instead of exponent.\n'+
                `Replacing memoryCost ${exp} with 2**${exp}=${2 ** exp}.\n`
      })
      options.memoryCost = 2 ** exp
    }

    if ('salt' in options) {
      return resolve()
    }

    crypto.randomBytes(16, (err, salt) => {
      if (err) {
        return reject(err)
      }
      options.salt = salt
      return resolve()
    })
  }).then(() => {
    return new Promise((resolve, reject) => {
      bindings.hash(Buffer.from(plain), options, resolve, reject)
    })
  }).then(hash => {
    if (options.raw) {
      return hash
    }

    return phc.serialize({
      id: type2string[options.type],
      version: options.version,
      params: {
        m: options.memoryCost,
        t: options.timeCost,
        p: options.parallelism,
      },
      salt: options.salt, hash,
    })
  })
}

const verify = (digest, plain) => {
  const {
    id: type, version, params: {
      m: memoryCost, t: timeCost, p: parallelism
    }, salt, hash
  } = phc.deserialize(digest)
  return new Promise((resolve, reject) => {
    const options = {
      type: module.exports[type],
      version: +version,
      hashLength: hash.length,
      memoryCost: +memoryCost,
      timeCost: +timeCost,
      parallelism: +parallelism,
      salt,
    }
    bindings.hash(Buffer.from(plain), options, resolve, reject)
  }).then(expected => expected.equals(hash))
}

module.exports = {
  defaults,
  limits,
  hash,
  verify
}

for (const k of Object.keys(types)) {
  module.exports[k] = types[k]
  type2string[types[k]] = k
}
