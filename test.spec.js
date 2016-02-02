const argon2 = require('./index');
const t = require('tap');

const password = 'password';
const salt = new Buffer('somesalt');

const limits = argon2.limits;
console.warn = () => {};

t.test('defaults', t => {
  'use strict';

  t.equivalent(argon2.defaults, {
    timeCost: 3,
    memoryCost: 12,
    parallelism: 1,
    argon2d: false
  });
  t.end();
});

t.test('basic async hash', t => {
  'use strict';

  t.plan(1);

  return argon2.hash(password, salt).then(hash => {
    t.equal(hash, '$argon2i$m=4096,t=3,p=1$c29tZXNhbHQ$vpOd0mbc3AzXEHMgcTb1CrZt5XuoRQuz1kQtGBv7ejk');
  });
}).catch(t.threw);

t.test('async hash with null in password', t => {
  'use strict';

  t.plan(1);

  return argon2.hash('pass\0word', salt).then(hash => {
    t.equal(hash, '$argon2i$m=4096,t=3,p=1$c29tZXNhbHQ$tcauj48oAe6NE/VLzTawLTQtmX848wkNs1d7z53ahNE');
  });
}).catch(t.threw);

t.test('async hash with argon2d', t => {
  'use strict';

  t.plan(1);

  return argon2.hash(password, salt, {
    argon2d: true
  }).then(hash => {
    t.match(hash, /\$argon2d\$/, 'Should have argon2d signature.');
  });
}).catch(t.threw);

t.test('async hash with truthy argon2d', t => {
  'use strict';

  t.plan(1);

  return argon2.hash(password, salt, {
    argon2d: 'foo'
  }).then(hash => {
    t.match(hash, /\$argon2d\$/, 'Should have argon2d signature.');
  });
}).catch(t.threw);

t.test('async hash with falsy argon2d', t => {
  'use strict';

  t.plan(1);

  return argon2.hash(password, salt, {
    argon2d: ''
  }).then(hash => {
    t.notMatch(hash, /\$argon2d\$/, 'Should not have argon2d signature.');
  });
}).catch(t.threw);

t.test('async hash with invalid salt', t => {
  'use strict';

  t.plan(1);

  return argon2.hash(password, 'stringsalt').catch(err => {
    t.match(err.message, /invalid salt.+must be a buffer/i);
  });
});

t.test('async hash with short salt', t => {
  'use strict';

  t.plan(1);

  return argon2.hash(password, salt.slice(0, 7)).catch(err => {
    t.match(err.message, /invalid salt.+with 8 or more bytes/i);
  });
});

t.test('async hash with time cost', t => {
  'use strict';

  t.plan(1);

  return argon2.hash(password, salt, {
    timeCost: 4
  }).then(hash => {
    t.match(hash, /t=4/, 'Should have correct time cost.');
  });
}).catch(t.threw);

t.test('async hash with invalid time cost', t => {
  'use strict';

  t.plan(1);

  return argon2.hash(password, salt, {
    timeCost: 'foo'
  }).catch(err => {
    t.match(err.message, /invalid timeCost.+must be an integer/i);
  });
});

t.test('async hash with low time cost', t => {
  'use strict';

  t.plan(1);

  return argon2.hash(password, salt, {
    timeCost: limits.timeCost.min - 1
  }).catch(err => {
    t.match(err.message, /invalid timeCost.+between \d+ and \d+/i);
  });
});

t.test('async hash with high time cost', t => {
  'use strict';

  t.plan(1);

  return argon2.hash(password, salt, {
    timeCost: limits.timeCost.max + 1
  }).catch(err => {
    t.match(err.message, /invalid timeCost.+between \d+ and \d+/i);
  });
});

t.test('async hash with memory cost', t => {
  'use strict';

  t.plan(1);

  return argon2.hash(password, salt, {
    memoryCost: 13
  }).then(hash => {
    t.match(hash, /m=8192/, 'Should have correct memory cost.');
  });
}).catch(t.threw);

t.test('async hash with invalid time cost', t => {
  'use strict';

  t.plan(1);

  return argon2.hash(password, salt, {
    memoryCost: 'foo'
  }).catch(err => {
    t.match(err.message, /invalid memoryCost.+must be an integer/i);
  });
});

t.test('async hash with low time cost', t => {
  'use strict';

  t.plan(1);

  return argon2.hash(password, salt, {
    memoryCost: limits.memoryCost.min - 1
  }).catch(err => {
    t.match(err.message, /invalid memoryCost.+between \d+ and \d+/i);
  });
});

t.test('async hash with high time cost', t => {
  'use strict';

  t.plan(1);

  return argon2.hash(password, salt, {
    memoryCost: limits.memoryCost.max + 1
  }).catch(err => {
    t.match(err.message, /invalid memoryCost.+between \d+ and \d+/i);
  });
});

t.test('async hash with parallelism', t => {
  'use strict';

  t.plan(1);

  return argon2.hash(password, salt, {
    parallelism: 2
  }).then(hash => {
    t.match(hash, /p=2/,  'Should have correct parallelism.');
  });
}).catch(t.threw);

t.test('async hash with invalid parallelism', t => {
  'use strict';

  t.plan(1);

  return argon2.hash(password, salt, {
    parallelism: 'foo'
  }).catch(err => {
    t.match(err.message, /invalid parallelism, must be an integer/i);
  });
});

t.test('async hash with low parallelism', t => {
  'use strict';

  t.plan(1);

  return argon2.hash(password, salt, {
    parallelism: limits.parallelism.min - 1
  }).catch(err => {
    t.match(err.message, /invalid parallelism.+between \d+ and \d+/i);
  });
});

t.test('async hash with high parallelism', t => {
  'use strict';

  t.plan(1);

  return argon2.hash(password, salt, {
    parallelism: limits.parallelism.max + 1
  }).catch(err => {
    t.match(err.message, /invalid parallelism.+between \d+ and \d+/i);
  });
});

t.test('async hash with all options', t => {
  'use strict';

  t.plan(1);

  return argon2.hash(password, salt, {
    timeCost: 4,
    memoryCost: 13,
    parallelism: 2
  }).then(hash => {
    t.match(hash, /m=8192,t=4,p=2/,  'Should have correct options.');
  });
}).catch(t.threw);

t.test('basic sync hash', t => {
  'use strict';

  const hash = argon2.hashSync(password, salt);
  t.equal(hash, '$argon2i$m=4096,t=3,p=1$c29tZXNhbHQ$vpOd0mbc3AzXEHMgcTb1CrZt5XuoRQuz1kQtGBv7ejk');
  t.end();
});

t.test('sync hash with null in password', t => {
  'use strict';

  const hash = argon2.hashSync('pass\0word', salt);
  t.equal(hash, '$argon2i$m=4096,t=3,p=1$c29tZXNhbHQ$tcauj48oAe6NE/VLzTawLTQtmX848wkNs1d7z53ahNE');
  t.end();
});

t.test('sync hash with argon2d', t => {
  'use strict';

  const hash = argon2.hashSync(password, salt, {
    argon2d: true
  });
  t.match(hash, /\$argon2d\$/,  'Should use argon2d signature.');
  t.end();
});

t.test('sync hash with truthy argon2d', t => {
  'use strict';

  const hash = argon2.hashSync(password, salt, {
    argon2d: 'foo'
  });
  t.match(hash, /\$argon2d\$/,  'Should use argon2d signature.');
  t.end();
});

t.test('sync hash with falsy argon2d', t => {
  'use strict';

  const hash = argon2.hashSync(password, salt, {
    argon2d: ''
  });
  t.match(hash, /\$argon2i\$/,  'Should not use argon2d signature.');
  t.end();
});

t.test('sync hash with invalid salt', t => {
  'use strict';

  t.throws(() => {
    argon2.hashSync(password, 'stringsalt');
  }, /invalid salt.+must be a buffer/i);
  t.end();
});

t.test('sync hash with short salt', t => {
  'use strict';

  t.throws(() => {
    argon2.hashSync(password, salt.slice(0, 7));
  }, /invalid salt.+with 8 or more bytes/i);
  t.end();
});

t.test('sync hash with time cost', t => {
  'use strict';

  const hash = argon2.hashSync(password, salt, {
    timeCost: 4
  });
  t.match(hash, /t=4/,  'Should have correct time cost.');
  t.end();
});

t.test('sync hash with invalid time cost', t => {
  'use strict';

  t.throws(() => {
    argon2.hashSync(password, salt, {
      timeCost: 'foo'
    });
  }, /invalid timeCost.+must be an integer/i);
  t.end();
});

t.test('sync hash with low time cost', t => {
  'use strict';

  t.throws(() => {
    argon2.hashSync(password, salt, {
      timeCost: limits.timeCost.min - 1
    });
  }, /invalid timeCost.+between \d+ and \d+/i);
  t.end();
});

t.test('sync hash with high time cost', t => {
  'use strict';

  t.throws(() => {
    argon2.hashSync(password, salt, {
      timeCost: limits.timeCost.max + 1
    });
  }, /invalid timeCost.+between \d+ and \d+/i);
  t.end();
});

t.test('sync hash with memory cost', t => {
  'use strict';

  const hash = argon2.hashSync(password, salt, {
    memoryCost: 13
  });
  t.match(hash, /m=8192/,  'Should have correct memory cost.');
  t.end();
});

t.test('sync hash with invalid memory cost', t => {
  'use strict';

  t.throws(() => {
    argon2.hashSync(password, salt, {
      memoryCost: 'foo'
    });
  }, /invalid memoryCost.+must be an integer/i);
  t.end();
});

t.test('sync hash with low memory cost', t => {
  'use strict';

  t.throws(() => {
    argon2.hashSync(password, salt, {
      memoryCost: limits.memoryCost.min - 1
    });
  }, /invalid memoryCost.+between \d+ and \d+/i);
  t.end();
});

t.test('sync hash with high memory cost', t => {
  'use strict';

  t.throws(() => {
    argon2.hashSync(password, salt, {
      memoryCost: limits.memoryCost.max + 1
    });
  }, /invalid memoryCost.+between \d+ and \d+/i);
  t.end();
});

t.test('sync hash with parallelism', t => {
  'use strict';

  const hash = argon2.hashSync(password, salt, {
    parallelism: 2
  });
  t.match(hash, /p=2/,  'Should have correct parallelism.');
  t.end();
});

t.test('sync hash with invalid parallelism', t => {
  'use strict';

  t.throws(() => {
    argon2.hashSync(password, salt, {
      parallelism: 'foo'
    });
  }, /invalid parallelism, must be an integer/i);
  t.end();
});

t.test('sync hash with low parallelism', t => {
  'use strict';

  t.throws(() => {
    argon2.hashSync(password, salt, {
      parallelism: limits.parallelism.min - 1
    });
  }, /invalid parallelism.+between \d+ and \d+/i);
  t.end();
});

t.test('sync hash with high parallelism', t => {
  'use strict';

  t.throws(() => {
    argon2.hashSync(password, salt, {
      parallelism: limits.parallelism.max + 1
    });
  }, /invalid parallelism.+between \d+ and \d+/i);
  t.end();
});

t.test('sync hash with all options', t => {
  'use strict';

  const hash = argon2.hashSync(password, salt, {
    timeCost: 4,
    memoryCost: 13,
    parallelism: 2
  });
  t.match(hash, /m=8192,t=4,p=2/,  'Should have correct options.');
  t.end();
});

t.test('async generate salt with default length', t => {
  'use strict';

  t.plan(1);

  return argon2.generateSalt().then(salt => {
    t.equal(salt.length, 16);
  });
}).catch(t.threw);

t.test('async generate salt with specified length', t => {
  'use strict';

  t.plan(1);

  return argon2.generateSalt(32).then(salt => {
    t.equal(salt.length, 32);
  });
}).catch(t.threw);

t.test('sync generate salt with default length', t => {
  'use strict';

  t.equal(argon2.generateSaltSync().length, 16);
  t.end();
});

t.test('sync generate salt with specified length', t => {
  'use strict';

  t.equal(argon2.generateSaltSync(32).length, 32);
  t.end();
});

t.test('async verify correct password', t => {
  'use strict';

  return argon2.generateSalt().then(salt => {
    return argon2.hash(password, salt).then(hash => {
      return argon2.verify(hash, password).then(t.pass);
    });
  });
}).catch(t.threw);

t.test('async verify wrong password', t => {
  'use strict';

  return argon2.generateSalt().then(salt => {
    return argon2.hash(password, salt).then(hash => {
      return argon2.verify(hash, 'passworld').catch(t.pass);
    });
  });
}).catch(t.threw);

t.test('async verify with null in password', t => {
  'use strict';

  return argon2.generateSalt().then(salt => {
    return argon2.hash('pass\0word', salt).then(hash => {
      return argon2.verify(hash, 'pass\0word').then(t.pass);
    });
  });
}).catch(t.threw);

t.test('async verify argon2d correct password', t => {
  'use strict';

  return argon2.generateSalt().then(salt => {
    return argon2.hash(password, salt, {
      argon2d: true
    }).then(hash => {
      return argon2.verify(hash, password).then(t.pass);
    });
  });
}).catch(t.threw);

t.test('async verify argon2d wrong password', t => {
  'use strict';

  return argon2.generateSalt().then(salt => {
    return argon2.hash(password, salt, {
      argon2d: true
    }).then(hash => {
      return argon2.verify(hash, 'passwolrd').catch(t.pass);
    });
  });
}).catch(t.threw);

t.test('sync verify correct password', t => {
  'use strict';

  t.plan(1);

  return argon2.generateSalt().then(salt => {
    return argon2.hash(password, salt).then(hash => {
      t.true(argon2.verifySync(hash, password));
    });
  });
}).catch(t.threw);

t.test('sync verify wrong password', t => {
  'use strict';

  t.plan(1);

  return argon2.generateSalt().then(salt => {
    return argon2.hash(password, salt).then(hash => {
      t.false(argon2.verifySync(hash, 'passworld'));
    });
  });
}).catch(t.threw);

t.test('sync verify with null in password', t => {
  'use strict';

  t.plan(1);

  return argon2.generateSalt().then(salt => {
    return argon2.hash('pass\0word', salt).then(hash => {
      t.true(argon2.verifySync(hash, 'pass\0word'));
    });
  });
}).catch(t.threw);

t.test('sync verify argon2d correct password', t => {
  'use strict';

  t.plan(1);

  return argon2.generateSalt().then(salt => {
    return argon2.hash(password, salt, {
      argon2d: true
    }).then(hash => {
      t.true(argon2.verifySync(hash, password));
    });
  });
}).catch(t.threw);

t.test('sync verify argon2d wrong password', t => {
  'use strict';

  t.plan(1);

  return argon2.generateSalt().then(salt => {
    return argon2.hash(password, salt, {
      argon2d: true
    }).then(hash => {
      t.false(argon2.verifySync(hash, 'passwolrd'));
    });
  });
}).catch(t.threw);
