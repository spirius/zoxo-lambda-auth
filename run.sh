#! /bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"

if test "$1" == "build"; then
    set -e
    mkdir -p build

    cp package.json package-lock.json build

    rsync -a src/. build/

    cd build

    npm install --production

    zip -r ../zoxo-build-prod.zip ./

    exit
fi

test -r ../zoxo-lambda-auth-config && source ../zoxo-lambda-auth-config

./node_modules/.bin/lambda-local \
    -l src/index.js \
    -h $1 \
    -e ./event-$1.js \
    -E '{"AWS_REGION": "eu-central-1"}' \
    -n -t 300
