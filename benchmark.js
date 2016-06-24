import 'any-promise/register/bluebird'
import {Suite} from 'benchmark'
import argon2 from './'

const f = (async () => {
  const password = 'password'
  const salt = await argon2.generateSalt()
  const hash = await argon2.hash(password, salt)

  const fixtures = {
    'basic hash': async deferred => {
      await argon2.hash(password, salt)
      deferred.resolve()
    },
    'time cost': async deferred => {
      await argon2.hash(password, salt, {
        timeCost: argon2.defaults.timeCost + 3
      })
      deferred.resolve()
    },
    'memory cost': async deferred => {
      await argon2.hash(password, salt, {
        memoryCost: argon2.defaults.memoryCost + 3
      })
      deferred.resolve()
    },
    'parallelism': async deferred => {
      await argon2.hash(password, salt, {
        parallelism: argon2.defaults.parallelism + 3
      })
      deferred.resolve()
    },
    'argon2d': async deferred => {
      await argon2.hash(password, salt, {
        argon2d: true
      })
      deferred.resolve()
    },
    'verify': async deferred => {
      await argon2.verify(hash, password)
      deferred.resolve()
    },
    'generate salt': async deferred => {
      await argon2.generateSalt()
      deferred.resolve()
    }
  }

  const suite = new Suite({
    onCycle(event) {
      console.log(event.target.toString())
    }
  })

  for (const item of Object.keys(fixtures)) {
    suite.add(item, fixtures[item], {defer: true})
  }

  suite.run({async: true})
})

f()
