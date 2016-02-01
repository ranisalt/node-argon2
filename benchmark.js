var argon2 = require('./'),
  async = require('async'),
  benchmark = require('async-benchmark');

var password = password;
var salt = argon2.generateSaltSync();
var hash = argon2.hashSync(password, salt);

var fixtures = [{
  name: 'argon2#hash',
  func: function (done) {
    argon2.hash(password, salt, done);
  }
}, {
  name: 'argon2#hashSync',
  func: function (done) {
    argon2.hashSync(password, salt);
    done();
  }
}, {
  name: 'argon2#verify',
  func: function (done) {
    argon2.verify(hash, password, done);
  }
}, {
  name: 'argon2#verifySync',
  func: function (done) {
    argon2.verifySync(hash, password);
    done();
  }
}, {
  name: 'argon2#generateSalt',
  func: function (done) {
    argon2.generateSalt(done);
  }
}, {
  name: 'argon2#generateSaltSync',
  func: function (done) {
    argon2.generateSaltSync();
    done();
  }
}];

async.eachSeries(fixtures, function iterator (item, callback) {
  benchmark(item.name, function (done) {
    item.func(done);
  }, function (err, event) {
    console.log(event.target.toString());
    callback(err);
  });
}, function (err) {
  if (err) {
    console.dir(err);
  }
});
