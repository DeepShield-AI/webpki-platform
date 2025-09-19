
-- 创建 tls 数据库
DROP DATABASE IF EXISTS `tls`;
CREATE DATABASE IF NOT EXISTS `tls` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `tls`;

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
    `leaf_sha256` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin,
    `chain_sha256` JSON,                     -- 证书哈希列表（JSON格式）
    `error` TEXT,                            -- 错误信息
    INDEX `idx_leaf_sha256` (`leaf_sha256`), -- 新增证书哈希索引
    INDEX `idx_host_ip` (`destination_host`, `destination_ip`)  -- 添加常用字段的复合索引
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

DROP TABLE IF EXISTS `web_security`;

CREATE TABLE IF NOT EXISTS `web_security` (
  `id` BIGINT NOT NULL PRIMARY KEY,
  `error_code` JSON
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- CREATE TABLE IF NOT EXISTS `web_security` (
--   `id` BIGINT NOT NULL PRIMARY KEY,
--   `error_code` JSON,
--   CONSTRAINT `fk_web_security_id`
--     FOREIGN KEY (`id`) REFERENCES `tlshandshake` (`id`) ON DELETE CASCADE
-- ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
