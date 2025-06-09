#!/bin/bash

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

function check_command {
    command -v "$1" >/dev/null 2>&1
}

function install_apt_package {
    echo -e "${GREEN}Installing $1 via apt...${NC}"
    sudo apt-get update
    sudo apt-get install -y "$1"
}

echo "==== Checking dependencies ===="

# Check Python 3.10+
if check_command python3; then
    PYTHON_VERSION=$(python3 -V 2>&1 | awk '{print $2}')
    if [[ "$(printf '%s\n' "3.10" "$PYTHON_VERSION" | sort -V | head -n1)" != "3.10" ]]; then
        echo -e "${RED}Python version is $PYTHON_VERSION, need >= 3.10${NC}"
        echo "Trying to install Python 3.10..."
        install_apt_package python3.10
    else
        echo -e "${GREEN}Python 3 found: $PYTHON_VERSION${NC}"
    fi
else
    install_apt_package python3
fi

# Check pip
if ! check_command pip3; then
    install_apt_package python3-pip
else
    echo -e "${GREEN}pip3 found${NC}"
fi

# Check Python venv for current version
PYVER=$(python3 -V | awk '{print $2}' | cut -d. -f1,2)
install_apt_package "python$PYVER-venv"

# Check zmap
if ! check_command zmap; then
    install_apt_package zmap
else
    echo -e "${GREEN}zmap found${NC}"
fi

# Check zgrab2
if ! check_command zgrab2; then
    echo -e "${RED}zgrab2 not found.${NC}"
    echo -e "${RED}请手动从 https://github.com/zmap/zgrab2 构建并安装 zgrab2${NC}"
else
    echo -e "${GREEN}zgrab2 found${NC}"
fi

# Check MySQL
if ! check_command mysql; then
    echo -e "${RED}MySQL client not found. Installing mysql-client${NC}"
    install_apt_package mysql-client
else
    echo -e "${GREEN}MySQL client found${NC}"
fi

if ! systemctl list-units --type=service | grep -q mysql; then
    echo -e "${RED}MySQL service not found. Installing mysql-server...${NC}"
    install_apt_package mysql-server
    echo "✅ 启动 MySQL 服务: sudo systemctl enable --now mysql"
else
    echo -e "${GREEN}MySQL service already installed${NC}"
fi

# Check Node.js and npm
if ! check_command npm || ! check_command node; then
    echo -e "${RED}Node.js/npm not found. Installing via NodeSource...${NC}"
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    install_apt_package nodejs
else
    echo -e "${GREEN}Node.js and npm found${NC}"
fi

# 安装 Redis
if ! check_command redis-server; then
    echo -e "${RED}Redis not found. Installing...${NC}"
    install_apt_package redis-server
else
    echo -e "${GREEN}Redis found${NC}"
fi

# 清空 Redis 数据
if check_command redis-cli; then
    redis-cli flushall
fi

echo -e "${GREEN}✅ All available dependencies are installed or checked.${NC}"
echo -e "${RED}⚠️ 请确保你已经手动构建和安装 zgrab2，并配置路径到 app/config/scan_config.py${NC}"

echo "==== Setting Up MySQL Schema ===="

if [ -f "./script/db_action/db.sql" ]; then
    echo "导入数据库初始化 SQL 脚本"
    echo -e "${RED}你需要输入 MySQL 密码（建议使用 root 用户）${NC}"
    mysql -u root -p < ./script/db_action/db.sql
    mysql -u root -p < ./script/db_action/init-db.sql
else
    echo -e "${RED}未找到 SQL 文件 ./script/db_action/db.sql，跳过数据库初始化${NC}"
    echo -e "${RED}未找到 SQL 文件 ./script/db_action/init-db.sql，跳过数据库初始化${NC}"
fi

echo "创建 MySQL User"
sudo mysql -e "CREATE USER IF NOT EXISTS 'tianyu'@'localhost' IDENTIFIED BY '123456';
GRANT ALL PRIVILEGES ON *.* TO 'tianyu'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;"

echo "==== Setting Up Python Environment ===="

rm -rf myenv
python3 -m venv myenv
source ./myenv/bin/activate
pip install --upgrade pip
pip install -e .

echo "==== Setting Up Frontend ===="

cd ui
npm install
cd ..

echo -e "${GREEN}✅ Platform setup is complete.${NC}"
