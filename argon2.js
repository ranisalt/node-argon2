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
}

const parser = /\$(argon2(?:i|d|id))\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)(?:,[^$]+)?\$([^$]+)\$([^$]+)/
const verify = (hash, plain) => {
  const [_, type, version, memoryCost, timeCost, parallelism, salt, encoded] = hash.match(parser)
  return new Promise((resolve, reject) => {
    const options = {
      type: module.exports[type],
      version: +version,
      memoryCost: Math.log2(+memoryCost),
      timeCost: +timeCost,
      parallelism: +parallelism,
      salt: Buffer.from(rightPad(salt), 'base64'),
      hashLength: Math.floor(encoded.length / 4 * 3)
    }
    bindings.hash(Buffer.from(plain), options, resolve, reject)
  }).then(expected => {
    return encoded === rightTrim(expected.toString('base64'))
  })
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
