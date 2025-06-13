#!/bin/bash

# Exit on error
set -e

# Navigate to the UI directory
if [ -d "ui" ]; then
  cd ui
else
  echo "Directory 'ui' does not exist!"
  exit 1
fi

# Workaround for Node.js/OpenSSL issue (see: https://stackoverflow.com/q/69692842)
export NODE_OPTIONS=--openssl-legacy-provider

# Start the dev server
npm run dev

# Return to original directory
cd ..
