import benchmark from 'benchmark'
import argon2 from './'

(async () => {
  console.log('Starting benchmark')
  const password = 'password'
  const salt = await argon2.generateSalt()
  const hash = await argon2.hash(password, salt)

  const fixtures = [{
    name: 'argon2#hash',
    func: async () => {
      await argon2.hash(password, salt)
    }
  }, {
    name: 'argon2#hashTimeCost',
    func: async () => {
      await argon2.hash(password, salt, {
        timeCost: argon2.defaults.timeCost + 3
      })
    }
  }, {
    name: 'argon2#hashMemoryCost',
    func: async () => {
      await argon2.hash(password, salt, {
        memoryCost: argon2.defaults.memoryCost + 3
      })
    }
  }, {
    name: 'argon2#hashParallelism',
    func: async () => {
      await argon2.hash(password, salt, {
        parallelism: argon2.defaults.parallelism + 3
      })
    }
  }, {
    name: 'argon2#hashArgon2d',
    func: async () => {
      await argon2.hash(password, salt, {
        argon2d: true
      })
    }
  }, {
    name: 'argon2#verify',
    func: async () => await argon2.verify(hash, password)
  }, {
    name: 'argon2#generateSalt',
    func: async () => await argon2.generateSalt()
  }]

  for (const item of fixtures) {
    benchmark(item.name, async () => {
      await item.func()
    }, (err, ev) => {
      console.log(ev.target.toString())
      console.log(err)
    })
  }
})()
