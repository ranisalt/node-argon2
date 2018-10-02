'use strict'
const crypto = require('crypto')
const { hash, limits, types, version } = require('bindings')('argon2')
const Promise = require('any-promise')
const phc = require('@phc/format')

let defaultHasher
class Hasher {
  // TODO: this is just for backwards compat, please create new Hasher instance
  static get hash () { return defaultHasher.hash.bind(defaultHasher) }
  static get needsRehash () { return defaultHasher.needsRehash.bind(defaultHasher) }
  static get verify () { return defaultHasher.verify.bind(defaultHasher) }

  static get argon2i () { return types.argon2i }
  static get argon2d () { return types.argon2d }
  static get argon2id () { return types.argon2id }
  static get defaults () {
    return {
      hashLength: 32,
      saltLength: 16,
      timeCost: 3,
      memoryCost: 1 << 12,
      parallelism: 1,
      type: Hasher.argon2i,
      version
    }
  }
  static get limits () { return limits }

  constructor (options) {
    this.options = Object.assign({}, Hasher.defaults, options)
  }

  hash (plain, options) {
    options = Object.assign({}, this.options, options)

    return new Promise((resolve, reject) => {
      for (const [key, {max, min}] of Object.entries(Hasher.limits)) {
        const value = options[key]
        if (value > max || value < min) {
          return reject(new Error(`Invalid ${key}, must be between ${min} and ${max}.`))
        }
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
        hash(Buffer.from(plain), Object.assign(options, {salt}), (err, value) => {
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

  needsRehash (digest, options) {
    options = Object.assign({}, Hasher.defaults, options)

    const {
      version, params: {m: memoryCost, t: timeCost}
    } = phc.deserialize(digest)
    return +version !== +options.version ||
      +memoryCost !== +options.memoryCost ||
      +timeCost !== +options.timeCost
  }

  verify (digest, plain) {
    const {
      id: type, version = 0x10, params: {
        m: memoryCost, t: timeCost, p: parallelism
      }, salt, hash: input
    } = phc.deserialize(digest)
    return new Promise((resolve, reject) => {
      const options = {
        type: Hasher[type],
        version: +version,
        hashLength: input.length,
        memoryCost: +memoryCost,
        timeCost: +timeCost,
        parallelism: +parallelism,
        salt
      }
      hash(Buffer.from(plain), options, (err, value) => {
        /* istanbul ignore if */
        if (err) {
          return reject(err)
        }
        return resolve(value.hash)
      })
    }).then(expected => expected.equals(input))
  }
}

defaultHasher = new Hasher()
module.exports = Hasher
