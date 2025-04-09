
CREATE DATABASE IF NOT EXISTS `scan_status` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci */ /*!80016 DEFAULT ENCRYPTION='N' */;
USE `scan_status`;

CREATE TABLE scan_status (
    `task_id` VARCHAR(64) PRIMARY KEY,
    `status` VARCHAR(32),
    `progress` VARCHAR(32),
    `run_time` FLOAT,
    `start_time` DATETIME,
    `last_update` DATETIME
);
