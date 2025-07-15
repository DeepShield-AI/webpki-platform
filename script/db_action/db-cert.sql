
-- 创建 cert 数据库
DROP DATABASE IF EXISTS `cert`;
CREATE DATABASE IF NOT EXISTS `cert` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `cert`;

DROP TABLE IF EXISTS `cert`;

CREATE TABLE IF NOT EXISTS `cert` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `sha256` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
  `cert_der` MEDIUMBLOB NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `ca_cert`;

CREATE TABLE IF NOT EXISTS `ca_cert` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `sha256` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
  `cert_der` MEDIUMBLOB NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `cert_fp`;

-- 创建 cert_fp 表，用于存储 cert_hash 和其对应的指纹（cert_fp）
CREATE TABLE IF NOT EXISTS `cert_fp` (
  `id` INT UNSIGNED NOT NULL PRIMARY KEY,
  `cert_fp` VARCHAR(128) NOT NULL,       -- 证书指纹
  CONSTRAINT `fk_cert_fp_cert_id`
    FOREIGN KEY (`id`) REFERENCES `cert` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

DROP TABLE IF EXISTS `cert_search`;

CREATE TABLE IF NOT EXISTS `cert_search` (
  `id` INT UNSIGNED NOT NULL PRIMARY KEY,
  `sha256` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,
  `serial` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin,
  `subject_cn_list` JSON,
  `subject` JSON,
  `issuer` JSON,
  `spkisha256` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  `ski` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin,
  `not_valid_before` DATETIME,
  `not_valid_after` DATETIME,
  CONSTRAINT `fk_cert_search_cert_id`
    FOREIGN KEY (`id`) REFERENCES `cert` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `cert_revocation`;

CREATE TABLE IF NOT EXISTS `cert_revocation` (
  `id`           INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,  -- 主键，自增唯一 ID
  `cert_id`      INT UNSIGNED NOT NULL,                             -- 关联证书 ID
  `type`         INT UNSIGNED NOT NULL,                             -- 撤销类型：CRL(0) / OCSP(1)
  `dist_point`   VARCHAR(256) NOT NULL,                             -- 分发点 URL
  `request_time` DATETIME NOT NULL,                                 -- 撤销检查时间
  `status`       INT UNSIGNED NOT NULL,                             -- 撤销状态（0=未吊销，1=吊销）
  `revoke_time`  DATETIME,                                          -- 实际吊销时间（可空）
  `reason_flag`  INT UNSIGNED,                                      -- 撤销原因码（可空）
  CONSTRAINT `fk_cert_revocation_cert_id`
    FOREIGN KEY (`cert_id`) REFERENCES `cert` (`id`) ON DELETE CASCADE,
  INDEX `idx_cert_id` (`cert_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
