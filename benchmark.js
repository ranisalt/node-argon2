const argon2 = require('./');
const async = require('async');
const benchmark = require('async-benchmark');

const password = 'password';
const salt = argon2.generateSaltSync();
const hash = argon2.hashSync(password, salt);

const fixtures = [{
  name: 'argon2#hash',
  func: (done) => argon2.hash(password, salt, done)
}, {
  name: 'argon2#hashSync',
  func: (done) => { argon2.hashSync(password, salt); done(); }
}, {
  name: 'argon2#hashTimeCost',
  func: (done) => { argon2.hash(password, salt, {
      timeCost: argon2.defaults.timeCost + 3
    }, done); }
}, {
  name: 'argon2#hashMemoryCost',
  func: (done) => { argon2.hash(password, salt, {
      memoryCost: argon2.defaults.memoryCost + 3
    }, done); }
}, {
  name: 'argon2#hashParallelism',
  func: (done) => { argon2.hash(password, salt, {
      parallelism: argon2.defaults.parallelism + 3
    }, done); }
}, {
  name: 'argon2#hashArgon2d',
  func: (done) => { argon2.hash(password, salt, {
      argon2d: true
    }, done); }
}, {
  name: 'argon2#verify',
  func: (done) => argon2.verify(hash, password, done)
}, {
  name: 'argon2#verifySync',
  func: (done) => { argon2.verifySync(hash, password); done(); }
}, {
  name: 'argon2#generateSalt',
  func: (done) => argon2.generateSalt(done)
}, {
  name: 'argon2#generateSaltSync',
  func: (done) => { argon2.generateSaltSync(); done(); }
}];

async.eachSeries(fixtures, (item, callback) => {
  benchmark(item.name, (done) => item.func(done), (err, ev) => {
    console.log(ev.target.toString());
    callback(err);
  });
}, (err) => {
  if (err) {
    console.dir(err);
  }
});
