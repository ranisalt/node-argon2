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
  saltLength: 16,
  timeCost: 3,
  memoryCost: 1 << 12,
  parallelism: 1,
  type: types.argon2i,
  version
})

const type2string = []

const hash = (plain, options) => {
  options = Object.assign({}, defaults, options)

  return new Promise((resolve, reject) => {
    for (const key of Object.keys(limits)) {
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
        detail: 'The argon2 package now uses value of memory cost instead of exponent.\n' +
        `Replacing memoryCost ${exp} with 2**${exp}=${1 << exp}.\n`
      })
      options.memoryCost = 1 << exp
    }

    if ('salt' in options) {
      return resolve(options.salt)
    }

    crypto.randomBytes(options.saltLength, (err, salt) => {
      /* istanbul ignore if */
      if (err) {
        return reject(err)
      }
      return resolve(salt)
    })
  }).then(salt => {
    return new Promise((resolve, reject) => {
      bindings.hash(Buffer.from(plain), Object.assign(options, {salt}), (err, value) => {
        /* istanbul ignore if */
        if (err) {
          return reject(err)
        }
        return resolve(value)
      })
    })
  }).then(output => {
    if (options.raw) {
      return output.hash
    }

    return phc.serialize(output)
  })
}

const needsRehash = (digest, options) => {
  options = Object.assign({}, defaults, options)

  const {
    version, params: {m: memoryCost, t: timeCost}
  } = phc.deserialize(digest)
  return +version !== +options.version ||
    +memoryCost !== +options.memoryCost ||
    +timeCost !== +options.timeCost
}

const verify = (digest, plain) => {
  const {
    id: type, version = 0x10, params: {
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
      salt
    }
    bindings.hash(Buffer.from(plain), options, (err, value) => {
      /* istanbul ignore if */
      if (err) {
        return reject(err)
      }
      return resolve(value.hash)
    })
  }).then(expected => expected.equals(hash))
}

module.exports = {
  defaults,
  limits,
  hash,
  needsRehash,
  verify
}

for (const k of Object.keys(types)) {
  module.exports[k] = types[k]
  type2string[types[k]] = k
}
