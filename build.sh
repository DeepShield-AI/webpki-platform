#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "========== [1/4] Building frontend =========="

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


echo -e "\n========== [2/4] Installing Nginx & uWSGI =========="

# Step 2: Install Nginx and uWSGI
echo "➡ Updating package list..."
sudo apt update

echo "➡ Installing nginx, uwsgi, and uwsgi-plugin-python3..."
sudo apt -y install nginx uwsgi uwsgi-plugin-python3

echo "➡ Enabling and starting Nginx..."
sudo systemctl enable nginx
sudo systemctl start nginx

echo "✅ Nginx & uWSGI installation complete."


echo -e "\n========== [3/4] Configuring Nginx =========="

echo "➡ Removing default site config and symlink..."
sudo rm -f /etc/nginx/sites-available/default
sudo rm -f /etc/nginx/sites-enabled/default

echo "➡ Copying new Nginx config to sites-available..."
sudo cp nginx.conf /etc/nginx/sites-available/flask

echo "➡ Creating symlink to sites-enabled..."
sudo ln -sf /etc/nginx/sites-available/flask /etc/nginx/sites-enabled/

echo "➡ Testing Nginx configuration..."
sudo nginx -t

echo "➡ Reloading Nginx..."
sudo systemctl reload nginx

echo "✅ Nginx configured successfully."


echo -e "\n========== [4/4] Starting uWSGI =========="

# Step 4: Start uWSGI

# TODO: check if there are already uwsgi running, and make it to the system service
echo "➡ Starting uWSGI with uwsgi.ini..."
uwsgi --ini uwsgi.ini

echo "✅ uWSGI started."


echo -e "\n🎉 [✓] Deployment completed successfully!"
