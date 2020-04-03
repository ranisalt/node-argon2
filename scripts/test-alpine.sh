#!/bin/sh

set -xe

echo "Running on $(node -v)"

apk add make g++ python

export npm_config_build_from_source=true
export npm_config_debug=true

yarn install --frozen-lockfile
yarn test
