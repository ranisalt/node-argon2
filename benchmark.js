import {Suite} from 'benchmark'
import argon2 from './'

(async () => {
  const password = 'password'
  const salt = await argon2.generateSalt()
  const hash = await argon2.hash(password, salt)

  const fixtures = {
    'argon2#hash': async deferred => {
      await argon2.hash(password, salt)
      deferred.resolve()
    },
    'argon2#hashTimeCost': async deferred => {
      await argon2.hash(password, salt, {
        timeCost: argon2.defaults.timeCost + 3
      })
      deferred.resolve()
    },
    'argon2#hashMemoryCost': async deferred => {
      await argon2.hash(password, salt, {
        memoryCost: argon2.defaults.memoryCost + 3
      })
      deferred.resolve()
    },
    'argon2#hashParallelism': async deferred => {
      await argon2.hash(password, salt, {
        parallelism: argon2.defaults.parallelism + 3
      })
      deferred.resolve()
    },
    'argon2#hashArgon2d': async deferred => {
      await argon2.hash(password, salt, {
        argon2d: true
      })
      deferred.resolve()
    },
    'argon2#verify': async deferred => {
      await argon2.verify(hash, password)
      deferred.resolve()
    },
    'argon2#generateSalt': async deferred => {
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
})()
