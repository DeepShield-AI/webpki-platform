#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "========== [1/4] Stopping MySQL =========="

systemctl stop mysql

echo "========== [2/4] Building frontend =========="

# Step 1: Build frontend static resources
cd ui || { echo "❌ Error: 'ui' directory not found."; exit 1; }

echo "➡ Setting OpenSSL legacy provider for compatibility..."
export NODE_OPTIONS=--openssl-legacy-provider

echo "➡ Running 'npm run build'..."
npm run build

echo "➡ Ensuring target directory /var/www/pki-internet-platform exists..."
sudo mkdir -p /var/www/pki-internet-platform

echo "➡ Removing old dist directory (if exists)..."
sudo rm -rf /var/www/pki-internet-platform/dist

echo "➡ Copying new build to /var/www/pki-internet-platform/dist..."
sudo cp -r dist /var/www/pki-internet-platform/dist

cd ..
echo "✅ Frontend build and deployment complete."

echo "========== [3/4] Restart MySQL =========="

systemctl start mysql

echo "========== [4/4] Restart Uwsgi =========="

uwsgi --reload uwsgi.pid
