
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
