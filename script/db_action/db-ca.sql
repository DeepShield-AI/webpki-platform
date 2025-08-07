
-- 创建 ca 数据库
DROP DATABASE IF EXISTS `ca`;
CREATE DATABASE IF NOT EXISTS `ca` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE `ca`;

DROP TABLE IF EXISTS `ca`;

CREATE TABLE IF NOT EXISTS `ca` (
  `id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `sha256` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE,  -- sha256 of subject and spki
  `subject` JSON,
  `spki` MEDIUMBLOB,
  `ski` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin,
  `certs` JSON,   -- list of owned certs with same sha256, with cert_id in it
  `issued_certs` INT,
  `parent` JSON,
  `child` JSON
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

DROP TABLE IF EXISTS `mozilla_root`;

CREATE TABLE IF NOT EXISTS `mozilla_root` (
  `sha256` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL UNIQUE PRIMARY KEY,  -- sha256 of subject and spki
  `trust` BOOLEAN
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
