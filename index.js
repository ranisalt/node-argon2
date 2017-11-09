'use strict'
const crypto = require('crypto')
const bindings = require('bindings')('argon2')
const Promise = require('any-promise')

const argon2d = 0
const argon2i = 1
const argon2id = 2

const defaults = Object.freeze({
  hashLength: 32,
  timeCost: 3,
  memoryCost: 12,
  parallelism: 1,
  type: argon2i,
  raw: false
})

const limits = Object.freeze(bindings.limits)

module.exports = {
  defaults,
  limits,
  argon2d,
  argon2i,
  argon2id,

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

      (options == null || options.saltGeneratorF == null ? crypto.randomBytes : options.saltGeneratorF)(16, (err, salt) => {
        if (err) {
          reject(err)
        }
        bindings.hash(Buffer.from(plain), salt, options, resolve, reject)
      })
    })
  },

  verify (hash, plain) {
    return new Promise((resolve, reject) => {
      bindings.verify(Buffer.from(hash), Buffer.from(plain), resolve, reject)
    })
  }
}
