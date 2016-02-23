import argon2 from './';
import t from 'tap';

const password = 'password';
const passwordWithNull = 'pass\0word';
const salt = new Buffer('somesalt');
const saltWithNull = new Buffer('\0abcdefghijklmno');

const truncatedBase64 = buffer => buffer.toString('base64').replace(/\=*$/, '');

const hashes = Object.freeze({
  argon2i: '$argon2i$m=4096,t=3,p=1$c29tZXNhbHQ$vpOd0mbc3AzXEHMgcTb1CrZt5XuoRQuz1kQtGBv7ejk',
  argon2d: '$argon2d$m=4096,t=3,p=1$c29tZXNhbHQ$/rwrGjZ1NrS+TEgQxricD7B57yJMKGQ/uov96abC6ko'
});

const limits = argon2.limits;

t.test('basic hash', async t => {
  const hash = await argon2.hash(password, salt);
  t.equal(hash, hashes.argon2i);
});

t.test('hash with null in password', async t => {
  const hash = await argon2.hash(passwordWithNull, salt);
  t.equal(hash, '$argon2i$m=4096,t=3,p=1$c29tZXNhbHQ$tcauj48oAe6NE/VLzTawLTQtmX848wkNs1d7z53ahNE');
});

t.test('hash with null in salt', async t => {
  const hash = await argon2.hash(password, saltWithNull);
  t.equal(hash.substring(23, 47), '$' + truncatedBase64(saltWithNull) + '$');
});

t.test('hash with longer salt', async t => {
  /* intentionally using a length that is not multiple of 3 */
  const hash = await argon2.hash(password, await argon2.generateSalt(500));
  t.match(hash, /.*\$.{667}\$/, 'Hash should use the entire salt');
});

t.test('hash with argon2d', async t => {
  const hash = await argon2.hash(password, salt, {
    argon2d: true
  });
  t.equal(hash, hashes.argon2d);

  t.match(await argon2.hash(password, salt, {
    argon2d: 'foo'
  }), /\$argon2d\$/, 'Should have argon2d signature.');

  t.notMatch(await argon2.hash(password, salt, {
    argon2d: ''
  }), /\$argon2d\$/, 'Should not have argon2d signature.');
});

t.test('hash with invalid salt', async t => {
  t.plan(2);

  try {
    await argon2.hash(password, 'stringsalt');
  } catch (err) {
    t.match(err.message, /invalid salt.+must be a buffer/i);
  }

  try {
    await argon2.hash(password, salt.slice(0, 7));
  } catch (err) {
    t.match(err.message, /invalid salt.+with 8 or more bytes/i);
  }

  t.end();
});

t.test('hash with time cost', async t => {
  const hash = await argon2.hash(password, salt, {
    timeCost: 4
  });
  t.match(hash, /t=4/, 'Should have correct time cost.');
});

t.test('hash with invalid time cost', async t => {
  t.plan(3);

  try {
    await argon2.hash(password, salt, {
      timeCost: 'foo'
    });
  } catch (err) {
    t.match(err.message, /invalid timeCost.+must be an integer/i);
  }

  try {
    await argon2.hash(password, salt, {
      timeCost: limits.timeCost.max + 1
    });
  } catch (err) {
    t.match(err.message, /invalid timeCost.+between \d+ and \d+/i);
  }

  try {
    await argon2.hash(password, salt, {
      timeCost: limits.timeCost.min - 1
    });
  } catch (err) {
    t.match(err.message, /invalid timeCost.+between \d+ and \d+/i);
  }

  t.end();
});

t.test('hash with memory cost', async t => {
  const hash = await argon2.hash(password, salt, {
    memoryCost: 13
  });
  t.match(hash, /m=8192/, 'Should have correct memory cost.');
});

t.test('hash with invalid memory cost', async t => {
  t.plan(3);

  try {
    await argon2.hash(password, salt, {
      memoryCost: 'foo'
    });
  } catch (err) {
    t.match(err.message, /invalid memoryCost.+must be an integer/i);
  }

  try {
    await argon2.hash(password, salt, {
      memoryCost: limits.memoryCost.max + 1
    });
  } catch (err) {
    t.match(err.message, /invalid memoryCost.+between \d+ and \d+/i);
  }

  try {
    await argon2.hash(password, salt, {
      memoryCost: limits.memoryCost.min - 1
    });
  } catch (err) {
    t.match(err.message, /invalid memoryCost.+between \d+ and \d+/i);
  }

  t.end();
});

t.test('hash with parallelism', async t => {
  const hash = await argon2.hash(password, salt, {
    parallelism: 2
  });
  t.match(hash, /p=2/, 'Should have correct parallelism.');
});

t.test('hash with invalid parallelism', async t => {
  t.plan(3);

  try {
    await argon2.hash(password, salt, {
      parallelism: 'foo'
    });
  } catch (err) {
    t.match(err.message, /invalid parallelism.+must be an integer/i);
  }

  try {
    await argon2.hash(password, salt, {
      parallelism: limits.parallelism.max + 1
    });
  } catch (err) {
    t.match(err.message, /invalid parallelism.+between \d+ and \d+/i);
  }

  try {
    await argon2.hash(password, salt, {
      parallelism: limits.parallelism.min - 1
    });
  } catch (err) {
    t.match(err.message, /invalid parallelism.+between \d+ and \d+/i);
  }

  t.end();
});

t.test('hash with all options', async t => {
  const hash = await argon2.hash(password, salt, {
    timeCost: 4,
    memoryCost: 13,
    parallelism: 2
  });
  t.match(hash, /m=8192,t=4,p=2/, 'Should have correct options.');
});

t.test('generate salt with default length', async t => {
  const salt = await argon2.generateSalt();
  t.equal(await salt.length, 16);
});

t.test('generate salt with specified length', async t => {
  const salt = await argon2.generateSalt(32);
  t.equal(await salt.length, 32);
});

t.test('verify correct password', async t => {
  t.true(await argon2.verify(hashes.argon2i, password));
});

t.test('verify wrong password', async t => {
  t.false(await argon2.verify(hashes.argon2i, 'passworld'));
});

t.test('verify with null in password', async t => {
  const hash = await argon2.hash(passwordWithNull, await argon2.generateSalt());
  t.true(await argon2.verify(hash, passwordWithNull));
});

t.test('verify argon2d correct password', async t => {
  t.true(await argon2.verify(hashes.argon2d, password));
});

t.test('verify argon2d wrong password', async t => {
  t.false(await argon2.verify(hashes.argon2d, 'passworld'));
});
