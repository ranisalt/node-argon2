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

const rightPad = encoded => encoded + '='.repeat(encoded.length % 4)
const rightTrim = encoded => encoded.replace(/=+$/, '')

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
      return new Promise((resolve, reject) => {
        if (options.raw) {
          return resolve(hash)
        }

        const algo = `$${type2string[options.type]}$v=${version}`
        const params = [
          `m=${1 << options.memoryCost}`,
          `t=${options.timeCost}`,
          `p=${options.parallelism}`
        ].join(',')
        const base64hash = rightTrim(hash.toString('base64'))
        const base64salt = rightTrim(options.salt.toString('base64'))
        return resolve([algo, params, base64salt, base64hash].join('$'))
      })
    })
  },

  verify (hash, plain, options) {
    options = Object.assign({}, options)
    const parsed = {}

    const sections = hash.split('$')
    return new Promise((resolve, reject) => {
      if ('type' in options) {
        return resolve()
      }

      parsed.type = types[sections[1]]
      return resolve()
    }).then(() => {
      return new Promise((resolve, reject) => {
        const params = sections[sections.length - 3]

        if (!('memoryCost' in options)) {
          const memoryCost = /m=(\d+)/.exec(params)
          parsed.memoryCost = Math.log2(+memoryCost[1])
        }

        if (!('timeCost' in options)) {
          const timeCost = /t=(\d+)/.exec(params)
          parsed.timeCost = +timeCost[1]
        }

        if (!('parallelism' in options)) {
          const parallelism = /p=(\d+)/.exec(params)
          parsed.parallelism = +parallelism[1]
        }

        return resolve()
      })
    }).then(() => {
      return new Promise((resolve, reject) => {
        if ('salt' in options) {
          return resolve()
        }

        const salt = sections[sections.length - 2]
        parsed.salt = Buffer.from(rightPad(salt), 'base64')
        return resolve()
      })
    }).then(() => {
      options = Object.assign({}, defaults, parsed, options)

      return new Promise((resolve, reject) => {
        return bindings.hash(Buffer.from(plain), options, resolve, reject)
      })
    }).then(raw => {
      const expected = sections[sections.length - 1]

      const base64hash = rightTrim(raw.toString('base64'))
      return Promise.resolve(base64hash === expected)
    })
  }
}

for (const k of Object.keys(types)) {
  module.exports[k] = types[k]
  type2string[types[k]] = k
}
