const argon2 = require('./index');
const spawn = require('child_process').spawn;
const t = require('tap');

const defaults = argon2.defaults;
const limits = argon2.limits;
const salt = 'somesalt';

// hashes for argon2i and argon2d with default options
const hashes = Object.freeze({
  argon2i: '\\$argon2i\\$m=4096,t=3,p=1\\$c29tZXNhbHQ\\$vpOd0mbc3AzXEHMgcTb1CrZt5XuoRQuz1kQtGBv7ejk',
  argon2d: '\\$argon2d\\$m=4096,t=3,p=1\\$c29tZXNhbHQ\\$/rwrGjZ1NrS+TEgQxricD7B57yJMKGQ/uov96abC6ko'
});

t.test('hash with defaults', t => {
  'use strict';

  t.plan(8);

  const child = spawn('./cli.js', [salt]);
  child.stdin.end('password');

  let outbuf = new Buffer(0);
  child.stdout.on('data', data => {
    outbuf = Buffer.concat([outbuf, data]);
  });

  child.stdout.on('end', () => {
    const output = outbuf.toString().split('\n');
    t.match(output[0], /Type:\s*Argon2i/);
    t.match(output[1], new RegExp(`Iterations:\\s*${defaults.timeCost}`));
    t.match(output[2], new RegExp(`Memory:\\s*${1 << defaults.memoryCost} KiB`));
    t.match(output[3], new RegExp(`Parallelism:\\s*${defaults.parallelism}`));
    t.match(output[4], new RegExp(`Encoded:\\s*${hashes.argon2i}`));
    t.match(output[5], /\d+.\d{3} seconds/);
    t.match(output[6], /Verification ok/);
  });

  child.on('close', code => {
    t.equal(code, 0);
  });
});

t.test('hash with generated salt', t => {
  'use strict';

  t.plan(3);

  const child = spawn('./cli.js');
  child.stdin.end('password');

  let outbuf = new Buffer(0);
  child.stdout.on('data', data => {
    outbuf = Buffer.concat([outbuf, data]);
  });

  child.stdout.on('end', () => {
    const output = outbuf.toString().split('\n');
    t.match(output[4], /Encoded:.*\$.{22}\$[^$]*$/);
    t.match(output[6], /Verification ok/);
  });

  child.on('close', code => {
    t.equal(code, 0);
  });
});

t.test('hash with argon2d', t => {
  'use strict';

  t.plan(4);

  const child = spawn('./cli.js', [salt, '-d']);
  child.stdin.end('password');

  let outbuf = new Buffer(0);
  child.stdout.on('data', data => {
    outbuf = Buffer.concat([outbuf, data]);
  });

  child.stdout.on('end', () => {
    const output = outbuf.toString().split('\n');
    t.match(output[0], /Type:\s*Argon2d/);
    t.match(output[4], /Encoded:.*\$argon2d\$/);
    t.match(output[6], /Verification ok/);
  });

  child.on('close', code => {
    t.equal(code, 0);
  });
});

t.test('hash with time cost', t => {
  'use strict';

  t.plan(4);

  const child = spawn('./cli.js', [salt, '-t', '4']);
  child.stdin.end('password');

  let outbuf = new Buffer(0);
  child.stdout.on('data', data => {
    outbuf = Buffer.concat([outbuf, data]);
  });

  child.stdout.on('end', () => {
    const output = outbuf.toString().split('\n');
    t.match(output[1], /Iterations:\s*4/);
    t.match(output[4], /Encoded:.*,t=4,/);
    t.match(output[6], /Verification ok/);
  });

  child.on('close', code => {
    t.equal(code, 0);
  });
});

t.test('hash with invalid time cost', t => {
  'use strict';

  t.plan(2);

  const child = spawn('./cli.js', [salt, '-t', 'foo']);
  child.stdin.end('password');

  let outbuf = new Buffer(0);
  child.stderr.on('data', data => {
    outbuf = Buffer.concat([outbuf, data]);
  });

  child.stderr.on('end', () => {
    const output = outbuf.toString();
    t.match(output, /Error: Invalid timeCost.+must be an integer/);
  });

  child.on('close', code => {
    t.equal(code, 22);
  });
});

t.test('hash with low time cost', t => {
  'use strict';

  t.plan(2);

  const child = spawn('./cli.js', [salt, '-t', limits.timeCost.min - 1]);
  child.stdin.end('password');

  let outbuf = new Buffer(0);
  child.stderr.on('data', data => {
    outbuf = Buffer.concat([outbuf, data]);
  });

  child.stderr.on('end', () => {
    const output = outbuf.toString();
    t.match(output, /Error: Invalid timeCost.+between \d+ and \d+/);
  });

  child.on('close', code => {
    t.equal(code, 22);
  });
});

t.test('hash with high time cost', t => {
  'use strict';

  t.plan(2);

  const child = spawn('./cli.js', [salt, '-t', limits.timeCost.max + 1]);
  child.stdin.end('password');

  let outbuf = new Buffer(0);
  child.stderr.on('data', data => {
    outbuf = Buffer.concat([outbuf, data]);
  });

  child.stderr.on('end', () => {
    const output = outbuf.toString();
    t.match(output, /Error: Invalid timeCost.+between \d+ and \d+/);
  });

  child.on('close', code => {
    t.equal(code, 22);
  });
});

t.test('hash with memory cost', t => {
  'use strict';

  t.plan(4);

  const child = spawn('./cli.js', [salt, '-m', '13']);
  child.stdin.end('password');

  let outbuf = new Buffer(0);
  child.stdout.on('data', data => {
    outbuf = Buffer.concat([outbuf, data]);
  });

  child.stdout.on('end', () => {
    const output = outbuf.toString().split('\n');
    t.match(output[2], /Memory:\s*8192 KiB/);
    t.match(output[4], /Encoded:.*\$m=8192,/);
    t.match(output[6], /Verification ok/);
  });

  child.on('close', code => {
    t.equal(code, 0);
  });
});

t.test('hash with invalid memory cost', t => {
  'use strict';

  t.plan(2);

  const child = spawn('./cli.js', [salt, '-m', 'foo']);
  child.stdin.end('password');

  let outbuf = new Buffer(0);
  child.stderr.on('data', data => {
    outbuf = Buffer.concat([outbuf, data]);
  });

  child.stderr.on('end', () => {
    const output = outbuf.toString();
    t.match(output, /Error: Invalid memoryCost.+must be an integer/);
  });

  child.on('close', code => {
    t.equal(code, 22);
  });
});

t.test('hash with low memory cost', t => {
  'use strict';

  t.plan(2);

  const child = spawn('./cli.js', [salt, '-m', limits.memoryCost.min - 1]);
  child.stdin.end('password');

  let outbuf = new Buffer(0);
  child.stderr.on('data', data => {
    outbuf = Buffer.concat([outbuf, data]);
  });

  child.stderr.on('end', () => {
    const output = outbuf.toString();
    t.match(output, /Error: Invalid memoryCost.+between \d+ and \d+/);
  });

  child.on('close', code => {
    t.equal(code, 22);
  });
});

t.test('hash with high memory cost', t => {
  'use strict';

  t.plan(2);

  const child = spawn('./cli.js', [salt, '-m', limits.memoryCost.max + 1]);
  child.stdin.end('password');

  let outbuf = new Buffer(0);
  child.stderr.on('data', data => {
    outbuf = Buffer.concat([outbuf, data]);
  });

  child.stderr.on('end', () => {
    const output = outbuf.toString();
    t.match(output, /Error: Invalid memoryCost.+between \d+ and \d+/);
  });

  child.on('close', code => {
    t.equal(code, 22);
  });
});

t.test('hash with parallelism', t => {
  'use strict';

  t.plan(4);

  const child = spawn('./cli.js', [salt, '-p', '2']);
  child.stdin.end('password');

  let outbuf = new Buffer(0);
  child.stdout.on('data', data => {
    outbuf = Buffer.concat([outbuf, data]);
  });

  child.stdout.on('end', () => {
    const output = outbuf.toString().split('\n');
    t.match(output[3], /Parallelism:\s*2/);
    t.match(output[4], /Encoded:.*,p=2\$/);
    t.match(output[6], /Verification ok/);
  });

  child.on('close', code => {
    t.equal(code, 0);
  });
});

t.test('hash with invalid parallelism', t => {
  'use strict';

  t.plan(2);

  const child = spawn('./cli.js', [salt, '-p', 'foo']);
  child.stdin.end('password');

  let outbuf = new Buffer(0);
  child.stderr.on('data', data => {
    outbuf = Buffer.concat([outbuf, data]);
  });

  child.stderr.on('end', () => {
    const output = outbuf.toString();
    t.match(output, /Error: Invalid parallelism.+must be an integer/);
  });

  child.on('close', code => {
    t.equal(code, 22);
  });
});

t.test('hash with low parallelism', t => {
  'use strict';

  t.plan(2);

  const child = spawn('./cli.js', [salt, '-p', limits.parallelism.min - 1]);
  child.stdin.end('password');

  let outbuf = new Buffer(0);
  child.stderr.on('data', data => {
    outbuf = Buffer.concat([outbuf, data]);
  });

  child.stderr.on('end', () => {
    const output = outbuf.toString();
    t.match(output, /Error: Invalid parallelism.+between \d+ and \d+/);
  });

  child.on('close', code => {
    t.equal(code, 22);
  });
});

t.test('hash with high parallelism', t => {
  'use strict';

  t.plan(2);

  const child = spawn('./cli.js', [salt, '-p', limits.parallelism.max + 1]);
  child.stdin.end('password');

  let outbuf = new Buffer(0);
  child.stderr.on('data', data => {
    outbuf = Buffer.concat([outbuf, data]);
  });

  child.stderr.on('end', () => {
    const output = outbuf.toString();
    t.match(output, /Error: Invalid parallelism.+between \d+ and \d+/);
  });

  child.on('close', code => {
    t.equal(code, 22);
  });
});

t.test('hash with all options', t => {
  'use strict';

  t.plan(7);

  const child = spawn('./cli.js', [salt, '-d', '-t', '4', '-m', '13', '-p', '2']);
  child.stdin.end('password');

  let outbuf = new Buffer(0);
  child.stdout.on('data', data => {
    outbuf = Buffer.concat([outbuf, data]);
  });

  child.stdout.on('end', () => {
    const output = outbuf.toString().split('\n');
    t.match(output[0], /Type:\s*Argon2d/);
    t.match(output[1], /Iterations:\s*4/);
    t.match(output[2], /Memory:\s*8192 KiB/);
    t.match(output[3], /Parallelism:\s*2/);
    t.match(output[4], /Encoded:.*\$argon2d\$m=8192,t=4,p=2\$/);
    t.match(output[6], /Verification ok/);
  });

  child.on('close', code => {
    t.equal(code, 0);
  });
});

t.test('hash quiet', t => {
  'use strict';

  t.plan(2);

  const child = spawn('./cli.js', [salt, '-q']);
  child.stdin.end('password');

  let outbuf = new Buffer(0);
  child.stdout.on('data', data => {
    outbuf = Buffer.concat([outbuf, data]);
  });

  child.stdout.on('end', () => {
    // trim the trailing newline
    const output = outbuf.toString().trim();
    t.match(output, new RegExp(`^${hashes.argon2i}$`));
  });

  child.on('close', code => {
    t.equal(code, 0);
  });
});
