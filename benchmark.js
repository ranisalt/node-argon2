const {Suite} = require('sandra')
const argon2 = require('./')

const main = async () => {
  const defaults = argon2.defaults
  const password = 'password'
  const hash = await argon2.hash(password)
  const suite = new Suite('argon2')

  suite.push('basic hash', argon2.hash, password)
  suite.push('basic raw hash', argon2.hash, password, {raw: true})
  suite.push('time cost', argon2.hash, password, {timeCost: defaults.timeCost + 1})
  suite.push('memory cost', argon2.hash, password, {memoryCost: defaults.memoryCost + 1})
  suite.push('parallelism', argon2.hash, password, {parallelism: defaults.parallelism + 1})
  suite.push('argon2d', argon2.hash, password, {type: argon2.argon2d})
  suite.push('argon2d raw hash', argon2.hash, password, {type: argon2.argon2d, raw: true})
  suite.push('argon2id', argon2.hash, password, {type: argon2.argon2id})
  suite.push('argon2id raw hash', argon2.hash, password, {type: argon2.argon2id, raw: true})
  suite.push('verify', argon2.verify, hash, password)

  suite.on('cycle', event => {
    console.log(event.toString())
  })

  await suite.run({
    timeout: 2500
  })
}

main()
