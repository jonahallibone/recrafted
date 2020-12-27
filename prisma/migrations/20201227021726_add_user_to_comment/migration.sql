/*
  Warnings:

  - You are about to drop the column `author` on the `comment` table. All the data in the column will be lost.
  - Added the required column `author_id` to the `comment` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE `comment` DROP COLUMN `author`,
    ADD COLUMN     `author_id` INT NOT NULL,
    MODIFY `y_coordinate` INT;

-- AddForeignKey
ALTER TABLE `comment` ADD FOREIGN KEY (`author_id`) REFERENCES `user`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
