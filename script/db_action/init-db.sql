
-- 创建 scan_status 数据库
DROP DATABASE IF EXISTS `scan_status`;
CREATE DATABASE IF NOT EXISTS `scan_status` 
    /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci */ 
    /*!80016 DEFAULT ENCRYPTION='N' */;
USE `scan_status`;

-- 创建 scan_status 表
CREATE TABLE IF NOT EXISTS `scan_status` (
    `task_id` VARCHAR(64) PRIMARY KEY,       -- 任务ID
    `task_name` VARCHAR(64),                 -- 任务名称
    `status` VARCHAR(64) NOT NULL,           -- 状态
    -- `status` ENUM('pending', 'running', 'completed', 'failed') NOT NULL,  -- 状态
    `progress` VARCHAR(32),                  -- 进度
    `run_time` FLOAT,                        -- 运行时长
    `start_time` DATETIME,                   -- 启动时间
    `last_update` DATETIME                   -- 最后更新时间
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 创建 cert 数据库
DROP DATABASE IF EXISTS `cert`;
CREATE DATABASE IF NOT EXISTS `cert` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `cert`;

-- 创建 cert 表
CREATE TABLE IF NOT EXISTS `cert` (
    `cert_hash` VARCHAR(64) PRIMARY KEY,      -- 证书哈希值
    `cert_pem` MEDIUMTEXT NOT NULL            -- 证书内容
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 创建 cert_fp 表，用于存储 cert_hash 和其对应的指纹（cert_fp）
CREATE TABLE IF NOT EXISTS `cert_fp` (
    `cert_hash` VARCHAR(64) NOT NULL,      -- 证书哈希值
    `cert_fp` VARCHAR(128) NOT NULL,       -- 证书指纹
    PRIMARY KEY (`cert_hash`),             -- 保证每个证书只有一个指纹
    FOREIGN KEY (`cert_hash`) REFERENCES `cert`(`cert_hash`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 创建 tls_handshake 数据库
DROP DATABASE IF EXISTS `tls_handshake`;
CREATE DATABASE IF NOT EXISTS `tls_handshake` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `tls_handshake`;

-- 创建 tlshandshake 表
CREATE TABLE IF NOT EXISTS `tlshandshake` (
    `id` BIGINT AUTO_INCREMENT PRIMARY KEY,  -- 自增ID
    `destination_host` VARCHAR(255),         -- 目标主机名 can be NULL if only ip is provided
    `destination_ip` VARCHAR(45) NOT NULL,   -- 目标IP地址
    `scan_time` DATETIME NOT NULL,           -- 扫描时间
    `jarm` VARCHAR(128),                     -- JARM 指纹
    `jarm_hash` VARCHAR(128),                -- JARM哈希
    `tls_version` VARCHAR(64),               -- TLS版本
    `tls_cipher` VARCHAR(128),               -- TLS密码套件
    `cert_hash_list` TEXT,                   -- 证书哈希列表（JSON格式）
    `error` TEXT,                            -- 错误信息
    INDEX `idx_host_ip` (`destination_host`, `destination_ip`)  -- 添加常用字段的复合索引
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
