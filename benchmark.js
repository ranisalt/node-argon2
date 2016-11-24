import {Suite} from 'sandra'
import argon2, {defaults} from './'

(async() => {
  const password = 'password'
  const salt = await argon2.generateSalt()
  const hash = await argon2.hash(password, salt)
  const suite = new Suite('argon2')

  suite.push('basic hash', argon2.hash, password, salt)
  suite.push('time cost', argon2.hash, password, salt, {timeCost: defaults.timeCost + 1})
  suite.push('memory cost', argon2.hash, password, salt, {memoryCost: defaults.memoryCost + 1})
  suite.push('parallelism', argon2.hash, password, salt, {parallelism: defaults.parallelism + 1})
  suite.push('argon2d', argon2.hash, password, salt, {type: argon2.argon2d})
  suite.push('argon2id', argon2.hash, password, salt, {type: argon2.argon2id})
  suite.push('verify', argon2.verify, hash, password)
  suite.push('generate salt', argon2.generateSalt)

  suite.on('cycle', event => {
    console.log(event.toString())
  })

  await suite.run({
    timeout: 2500
  })
})()
