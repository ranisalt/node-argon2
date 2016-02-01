const argon2 = require('./'),
  async = require('async'),
  benchmark = require('async-benchmark');

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
  benchmark(item.name, (done) => item.func(done), (err, event) => {
    console.log(event.target.toString());
    callback(err);
  });
}, (err) => {
  if (err) {
    console.dir(err);
  }
});
