#!/bin/sh

set -xe

echo "Running on $(node -v)"

apk add make g++ python

export npm_config_build_from_source=true

yarn install --frozen-lockfile
yarn node-pre-gyp package
