#!/bin/bash

set -e

# ===== Colored Output =====
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# ===== Check if a command exists =====
function check_command {
    command -v "$1" >/dev/null 2>&1
}

# ===== Install APT Package =====
function install_apt_package {
    echo -e "${GREEN}Installing $1 via apt...${NC}"
    
    if ! grep -q "tuna.tsinghua.edu.cn" /etc/apt/sources.list; then
        echo -e "${GREEN}Switching to Tsinghua mirror...${NC}"
        sudo sed -i.bak -E 's|http://([a-z\.]*\.)?ubuntu\.com|https://mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list
    fi

    sudo apt-get update
    sudo apt-get install -y "$1"
}

echo "==== Setting Up Python Environment ===="

# --- Check Python 3.10+ ---
if check_command python3; then
    PYTHON_VERSION=$(python3 -V 2>&1 | awk '{print $2}')
    if [[ "$(printf '%s\n' "3.10" "$PYTHON_VERSION" | sort -V | head -n1)" != "3.10" ]]; then
        echo -e "${RED}Python version is $PYTHON_VERSION. Required >= 3.10${NC}"
        echo "Attempting to install Python 3.10..."
        install_apt_package python3.10
    else
        echo -e "${GREEN}Python 3 found: $PYTHON_VERSION${NC}"
    fi
else
    install_apt_package python3
fi

# --- Check pip3 ---
if ! check_command pip3; then
    install_apt_package python3-pip
else
    echo -e "${GREEN}pip3 found${NC}"
fi

# --- Install Python venv ---
PYVER=$(python3 -V | awk '{print $2}' | cut -d. -f1,2)
install_apt_package "python$PYVER-venv"

rm -rf myenv
python3 -m venv myenv
source ./myenv/bin/activate
pip install --upgrade pip -i https://pypi.tuna.tsinghua.edu.cn/simple
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -e .

echo "==== Setting Up MySQL Service ===="

# --- Check MySQL client and server ---
if ! check_command mysql; then
    echo -e "${RED}MySQL client not found. Installing...${NC}"
    install_apt_package mysql-client
else
    echo -e "${GREEN}MySQL client found${NC}"
fi

if ! sudo systemctl list-units --type=service | grep -q mysql; then
    echo -e "${RED}MySQL service not found. Installing...${NC}"
    install_apt_package mysql-server
    echo "You can start it with: sudo systemctl enable --now mysql"
else
    echo -e "${GREEN}MySQL service already installed${NC}"
fi

# --- Configuration Parameters ---
INNODB_SIZE="1G"
MEMORY_MAX="1.5G"
INNODB_SIZE_BYTES=$((1024 * 1024 * 1024))

# --- Locate MySQL config file ---
CONFIG_FILES=(
  "/etc/mysql/mysql.conf.d/mysqld.cnf"
  "/etc/mysql/my.cnf"
  "/etc/my.cnf"
)

for FILE in "${CONFIG_FILES[@]}"; do
  if [ -f "$FILE" ]; then
    CONFIG_FILE="$FILE"
    break
  fi
done

if [ -z "$CONFIG_FILE" ]; then
  echo -e "${RED}MySQL configuration file not found${NC}"
  exit 1
fi

echo -e "${GREEN}Found configuration file: $CONFIG_FILE${NC}"

# --- Backup and Modify innodb_buffer_pool_size ---
sudo cp "$CONFIG_FILE" "${CONFIG_FILE}.bak.$(date +%Y%m%d%H%M%S)"
echo "Backed up original config file"

if grep -q "innodb_buffer_pool_size" "$CONFIG_FILE"; then
  sudo sed -i "s/^innodb_buffer_pool_size.*/innodb_buffer_pool_size = $INNODB_SIZE_BYTES/" "$CONFIG_FILE"
  echo "Updated innodb_buffer_pool_size = $INNODB_SIZE_BYTES"
else
  sudo sed -i "/^\[mysqld\]/a innodb_buffer_pool_size = $INNODB_SIZE_BYTES" "$CONFIG_FILE"
  echo "Added innodb_buffer_pool_size to [mysqld] block"
fi

# --- Configure systemd MemoryMax ---
echo "Setting systemd MemoryMax = $MEMORY_MAX"

sudo mkdir -p /etc/systemd/system/mysql.service.d
sudo cat <<EOF | sudo tee /etc/systemd/system/mysql.service.d/override.conf > /dev/null
[Service]
MemoryMax=$MEMORY_MAX
EOF

# --- Reload systemd and restart MySQL ---
echo "Reloading systemd and restarting MySQL..."

sudo systemctl daemon-reexec
sudo systemctl daemon-reload

if sudo systemctl restart mysql 2>/dev/null || sudo systemctl restart mysqld 2>/dev/null; then
  echo -e "${GREEN}MySQL restarted successfully. Memory limit applied.${NC}"
else
  echo -e "${RED}Failed to restart MySQL. Check if service is named mysql or mysqld${NC}"
fi

echo "==== Initializing MySQL Schema ===="

if [ -f "./script/db_action/db.sql" ]; then
    echo "Importing database initialization script..."
    sudo mysql < ./script/db_action/db.sql
    sudo mysql < ./script/db_action/init-db.sql
    sudo mysql < ./script/db_action/db-new.sql
else
    echo -e "${RED}SQL file not found. Skipping initialization.${NC}"
fi

echo "Creating MySQL user 'tianyu'"

sudo mysql -e "CREATE USER IF NOT EXISTS 'tianyu'@'localhost' IDENTIFIED BY '123456';
GRANT ALL PRIVILEGES ON *.* TO 'tianyu'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;"

echo "==== Checking ZMAP ===="

# --- Check zmap ---
if ! check_command zmap; then
    install_apt_package zmap
else
    echo -e "${GREEN}zmap found${NC}"
fi

echo "==== Checking Redis ===="

if ! check_command redis-server; then
    echo -e "${RED}Redis not found. Installing...${NC}"
    install_apt_package redis-server
else
    echo -e "${GREEN}Redis found${NC}"
fi

echo "Flushing Redis data"

if check_command redis-cli; then
    redis-cli flushall
fi

echo "==== Installing Node.js and Frontend Dependencies ===="

if ! check_command curl; then
    echo -e "${RED}curl not found. Installing...${NC}"
    install_apt_package curl
else
    echo -e "${GREEN}curl found${NC}"
fi

if ! check_command npm || ! check_command node; then
    echo -e "${RED}Node.js/npm not found. Installing via NodeSource...${NC}"
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    install_apt_package nodejs
else
    echo -e "${GREEN}Node.js and npm found${NC}"
fi

echo "Installing frontend packages"

cd ui
npm install
cd ..

echo -e "${GREEN}Platform setup complete.${NC}"
