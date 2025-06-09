#!/bin/bash


cd ui

# make sure this exists:
# from https://stackoverflow.com/questions/69692842/error-message-error0308010cdigital-envelope-routinesunsupported
export NODE_OPTIONS=--openssl-legacy-provider
npm run dev

cd ..
