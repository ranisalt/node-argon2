import {Suite} from 'benchmark'
import argon2 from './'

(async () => {
  const password = 'password'
  const salt = await argon2.generateSalt()
  const hash = await argon2.hash(password, salt)

  const fixtures = {
    'argon2#hash': async () => {
      await argon2.hash(password, salt)
    },
    'argon2#hashTimeCost': async () => {
      await argon2.hash(password, salt, {
        timeCost: argon2.defaults.timeCost + 3
      })
    },
    'argon2#hashMemoryCost': async () => {
      await argon2.hash(password, salt, {
        memoryCost: argon2.defaults.memoryCost + 3
      })
    },
    'argon2#hashParallelism': async () => {
      await argon2.hash(password, salt, {
        parallelism: argon2.defaults.parallelism + 3
      })
    },
    'argon2#hashArgon2d': async () => {
      await argon2.hash(password, salt, {
        argon2d: true
      })
    },
    'argon2#verify': async () => await argon2.verify(hash, password),
    'argon2#generateSalt': async () => await argon2.generateSalt()
  }

  const suite = new Suite()
  for (const item of Object.keys(fixtures)) {
    suite.add(item, async () => {
      await fixtures[item]
    })
  }
  suite.on('cycle', event => {
    console.log(event.target.toString())
  }).run()
})()
