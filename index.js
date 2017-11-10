'use strict'
const crypto = require('crypto')
const bindings = require('bindings')('argon2')
const Promise = require('any-promise')

const limits = Object.freeze(bindings.limits)
const types = Object.freeze(bindings.types)
const version = bindings.version

const defaults = Object.freeze({
  hashLength: 32,
  timeCost: 3,
  memoryCost: 12,
  parallelism: 1,
  type: types.argon2i,
  raw: false
})

const type2string = []

module.exports = {
  defaults,
  limits,

  hash (plain, options) {
    options = Object.assign({}, defaults, options)

    return new Promise((resolve, reject) => {
      for (let key of Object.keys(limits)) {
        const {max, min} = limits[key]
        const value = options[key]
        if (value > max || value < min) {
          reject(new Error(`Invalid ${key}, must be between ${min} and ${max}.`))
        }
      }

      if ('salt' in options) {
        return resolve()
      }

      crypto.randomBytes(16, (err, salt) => {
        if (err) {
          reject(err)
        }
        options.salt = salt
        resolve()
      })
    }).then(() => {
      return new Promise((resolve, reject) => {
        bindings.hash(Buffer.from(plain), options, resolve, reject)
      })
    }).then(hash => {
      return new Promise((resolve, reject) => {
        if (options.raw) {
          resolve(hash)
        }

        const algo = `$${type2string[options.type]}$v=${version}`
        const params = [
          `m=${1 << options.memoryCost}`,
          `t=${options.timeCost}`,
          `p=${options.parallelism}`
        ].join(',')
        const base64hash = hash.toString('base64').replace(/=/g, '')
        const base64salt = options.salt.toString('base64').replace(/=/g, '')
        resolve([algo, params, base64salt, base64hash].join('$'))
      })
    })
  },

  verify (hash, plain) {
    return new Promise((resolve, reject) => {
      bindings.verify(Buffer.from(hash), Buffer.from(plain), resolve, reject)
    })
  }
}

for (const k of Object.keys(types)) {
  module.exports[k] = types[k]
  type2string[types[k]] = k
}
