-- CreateTable
CREATE TABLE `asset` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,
    `type` VARCHAR(191) NOT NULL,
    `status` VARCHAR(191) NOT NULL,
    `project_id` INT NOT NULL,
    `name` VARCHAR(191) NOT NULL,
INDEX `asset_project_id_index`(`project_id`),

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `comment` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,
    `description` VARCHAR(191) NOT NULL,
    `x_coordinate` INT,
    `y_coordinate` INT NOT NULL,
    `is_annotation` BOOLEAN NOT NULL,
    `author` JSON NOT NULL,
    `revision_id` INT NOT NULL,
INDEX `comment_revision_id_index`(`revision_id`),

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `file` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,
    `src` VARCHAR(191) NOT NULL,
    `is_original` BOOLEAN NOT NULL,
    `revision_id` INT NOT NULL,
    `file_size` INT NOT NULL,
    `mime_type` VARCHAR(191) NOT NULL,
    `file_extension` VARCHAR(191) NOT NULL,
    `height` INT,
    `width` INT,
INDEX `file_revision_id_index`(`revision_id`),

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `project` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,
    `project_name` VARCHAR(191) NOT NULL,
    `thumbnail_color` VARCHAR(191) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `revision` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,
    `version` INT NOT NULL,
    `asset_id` INT NOT NULL,
INDEX `revision_asset_id_index`(`asset_id`),

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `user` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,
    `name` VARCHAR(191) NOT NULL,
    `sub` VARCHAR(191) NOT NULL,
    `email` VARCHAR(191) NOT NULL,
UNIQUE INDEX `user.sub_unique`(`sub`),
UNIQUE INDEX `user.email_unique`(`email`),

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `user_project` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,
    `user_id` INT,
    `project_id` INT,
    `is_active` BOOLEAN NOT NULL,
    `is_author` BOOLEAN NOT NULL,
UNIQUE INDEX `user_project.project_id_unique`(`project_id`),
INDEX `user_project_project_id_index`(`project_id`),
INDEX `user_project_user_id_index`(`user_id`),

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `project_invitation` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,
    `sender_id` INT NOT NULL,
    `project_id` INT NOT NULL,
    `recipient` VARCHAR(191) NOT NULL,
    `expires_at` DATETIME(3),
    `email_code` VARCHAR(191) NOT NULL,
UNIQUE INDEX `project_invitation.email_code_unique`(`email_code`),

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `asset` ADD FOREIGN KEY (`project_id`) REFERENCES `project`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `comment` ADD FOREIGN KEY (`revision_id`) REFERENCES `revision`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `file` ADD FOREIGN KEY (`revision_id`) REFERENCES `revision`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `revision` ADD FOREIGN KEY (`asset_id`) REFERENCES `asset`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `user_project` ADD FOREIGN KEY (`project_id`) REFERENCES `project`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `user_project` ADD FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `project_invitation` ADD FOREIGN KEY (`sender_id`) REFERENCES `user`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `project_invitation` ADD FOREIGN KEY (`project_id`) REFERENCES `project`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
