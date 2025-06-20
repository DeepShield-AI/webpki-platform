
USE `cert`;
DROP TABLE IF EXISTS `cert_search_basic`;

-- cert_search_basic: 用于证书基础信息的搜索
CREATE TABLE IF NOT EXISTS `cert_search_basic` (
  `sha256` VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `subject_cn_list` JSON,
  `subject_org` VARCHAR(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci,
  `issuer_cn` VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `issuer_org` VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `issuer_country` VARCHAR(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `not_valid_before` DATETIME NOT NULL,
  `not_valid_after` DATETIME NOT NULL,
  PRIMARY KEY (`sha256`) USING BTREE,
  CONSTRAINT `fk_cert_search_basic_cert`
    FOREIGN KEY (`sha256`) REFERENCES `cert` (`cert_hash`)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
