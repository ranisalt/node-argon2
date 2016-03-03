#!/usr/bin/env node
'use strict';

const argon2 = require('./');
const argparse = require('argparse');

const hash = (password, args) => {
  const options = {
    argon2d: args.argon2d,
    timeCost: parseInt(args.timeCost, 10),
    memoryCost: parseInt(args.memoryCost, 10),
    parallelism: parseInt(args.parallelism, 10)
  };

  const generateSalt = args.salt === null ? argon2.generateSalt() :
      Promise.resolve(new Buffer(args.salt));

  return generateSalt.then(salt => {
    const start = Date.now();
    return argon2.hash(password, salt, options).then(hash => {
      const delta = Date.now() - start;

      if (args.quiet) {
        console.info(hash);
      } else {
        console.info('Type: \t\t%s', args.argon2d ? 'Argon2d' : 'Argon2i');
        console.info('Iterations: \t%d', args.timeCost);
        console.info('Memory: \t%d KiB', 1 << args.memoryCost);
        console.info('Parallelism: \t%d', args.parallelism);
        console.info('Encoded: \t%s', hash);
        console.info('%s seconds', (delta / 1000).toFixed(3));

        return argon2.verify(hash, password).then(result => {
          console.info('Verification %s', result ? 'ok' : 'failed');
        });
      }
    });
  }).catch(err => {
    console.error('Error: %s', err.message);

    // invalid argument error
    process.exit(22);
  });
};

const main = () => {
  const defaults = argon2.defaults;

  const parser = new argparse.ArgumentParser({
    prog: 'argon2',
    usage: 'argon2 salt [-d] [-t iterations] [-m memory] [-p parallelism]' +
      '\n\tPassword is read from stdin'
  });
  parser.addArgument(['salt'], {
    nargs: '?'
  });
  parser.addArgument(['-d', '--argon2d'], {
    action: 'storeTrue',
    dest: 'argon2d',
    help: `Use Argon2d instead of Argon2i (default: ${defaults.argon2d})`
  });
  parser.addArgument(['-m'], {
    defaultValue: defaults.memoryCost,
    dest: 'memoryCost',
    help: `Sets the memory usage to 2^N KiB (default: ${defaults.memoryCost})`,
    metavar: 'N'
  });
  parser.addArgument(['-t'], {
    defaultValue: defaults.timeCost,
    dest: 'timeCost',
    help: `Sets the number of iterations to N (default: ${defaults.timeCost})`,
    metavar: 'N'
  });
  parser.addArgument(['-p'], {
    defaultValue: defaults.parallelism,
    dest: 'parallelism',
    help: `Sets parallelism to N threads (default: ${defaults.parallelism})`,
    metavar: 'N'
  });
  parser.addArgument(['-q'], {
    action: 'storeTrue',
    dest: 'quiet',
    help: `Do not output timing information (default: false)`
  });
  const args = parser.parseArgs();

  let password = new Buffer(0);
  process.stdin.on('data', data => {
    password = Buffer.concat([password, data]);
  });
  process.stdin.on('end', () => {
    hash(password, args);
  });
};

main();
