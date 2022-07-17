ALTER TABLE `announcements` ADD COLUMN `course_name` VARCHAR(255) NOT NULL;
UPDATE `announcements` a JOIN `courses` b ON a.`course_id` = b.`id` SET `a`.`course_name` = `b`.`name`;
