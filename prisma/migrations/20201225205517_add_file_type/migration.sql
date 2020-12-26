-- AlterTable
ALTER TABLE `file` ADD COLUMN     `type` VARCHAR(191) NOT NULL DEFAULT 'original',
    MODIFY `is_original` BOOLEAN NOT NULL DEFAULT true;
