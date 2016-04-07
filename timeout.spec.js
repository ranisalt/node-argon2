const argon2 = require('./');
const t = require('tap');

t.test('js promise + setInterval', t => {
  'use strict';

  t.plan(1);
  let timer = setInterval(() => {
    /* istanbul ignore next */
    t.fail('Interval expired first');
  }, 5e3);

  return argon2.hash('password', new Buffer('somesalt')).then(() => {
    clearInterval(timer);
    t.pass();
  });
});

t.test('js promise + setTimeout', t => {
  'use strict';

  t.plan(1);
  let timer = setTimeout(() => {
    /* istanbul ignore next */
    t.fail('Timeout expired first');
  }, 5e3);

  return argon2.hash('password', new Buffer('somesalt')).then(() => {
    clearTimeout(timer);
    t.pass();
  });
});
