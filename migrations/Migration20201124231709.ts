import { Migration } from '@mikro-orm/migrations';

export class Migration20201124231709 extends Migration {

  async up(): Promise<void> {
    this.addSql('create table `user` (`id` int unsigned not null auto_increment primary key, `created_at` datetime not null, `updated_at` datetime not null, `name` varchar(255) not null, `sub` varchar(255) not null, `email` varchar(255) not null) default character set utf8mb4 engine = InnoDB;');
    this.addSql('alter table `user` add unique `user_sub_unique`(`sub`);');
    this.addSql('alter table `user` add unique `user_email_unique`(`email`);');

    this.addSql('create table `project` (`id` int unsigned not null auto_increment primary key, `created_at` datetime not null, `updated_at` datetime not null, `project_name` varchar(255) not null) default character set utf8mb4 engine = InnoDB;');

    this.addSql('create table `user_project` (`id` int unsigned not null auto_increment primary key, `created_at` datetime not null, `updated_at` datetime not null, `user_id` int(11) unsigned null, `project_id` int(11) unsigned null, `is_active` tinyint(1) not null, `is_author` tinyint(1) not null) default character set utf8mb4 engine = InnoDB;');
    this.addSql('alter table `user_project` add index `user_project_user_id_index`(`user_id`);');
    this.addSql('alter table `user_project` add index `user_project_project_id_index`(`project_id`);');
    this.addSql('alter table `user_project` add unique `user_project_project_id_unique`(`project_id`);');

    this.addSql('create table `asset` (`id` int unsigned not null auto_increment primary key, `created_at` datetime not null, `updated_at` datetime not null, `type` varchar(255) not null, `status` varchar(255) not null, `project_id` int(11) unsigned not null) default character set utf8mb4 engine = InnoDB;');
    this.addSql('alter table `asset` add index `asset_project_id_index`(`project_id`);');

    this.addSql('create table `revision` (`id` int unsigned not null auto_increment primary key, `created_at` datetime not null, `updated_at` datetime not null, `version` int(11) not null, `asset_id` int(11) unsigned not null) default character set utf8mb4 engine = InnoDB;');
    this.addSql('alter table `revision` add index `revision_asset_id_index`(`asset_id`);');

    this.addSql('create table `file` (`id` int unsigned not null auto_increment primary key, `created_at` datetime not null, `updated_at` datetime not null, `src` varchar(255) not null, `is_original` tinyint(1) not null, `revision_id` int(11) unsigned not null) default character set utf8mb4 engine = InnoDB;');
    this.addSql('alter table `file` add index `file_revision_id_index`(`revision_id`);');

    this.addSql('create table `comment` (`id` int unsigned not null auto_increment primary key, `created_at` datetime not null, `updated_at` datetime not null, `description` varchar(255) not null, `x_coordinate` int(11) null, `y_coordinate` int(11) not null, `is_annotation` tinyint(1) not null, `author` json not null, `revision_id` int(11) unsigned not null) default character set utf8mb4 engine = InnoDB;');
    this.addSql('alter table `comment` add index `comment_revision_id_index`(`revision_id`);');

    this.addSql('create table `base_entity` (`id` int unsigned not null auto_increment primary key, `created_at` datetime not null, `updated_at` datetime not null) default character set utf8mb4 engine = InnoDB;');

    this.addSql('alter table `user_project` add constraint `user_project_user_id_foreign` foreign key (`user_id`) references `user` (`id`) on update cascade on delete set null;');
    this.addSql('alter table `user_project` add constraint `user_project_project_id_foreign` foreign key (`project_id`) references `project` (`id`) on update cascade on delete set null;');

    this.addSql('alter table `asset` add constraint `asset_project_id_foreign` foreign key (`project_id`) references `project` (`id`) on update cascade;');

    this.addSql('alter table `revision` add constraint `revision_asset_id_foreign` foreign key (`asset_id`) references `asset` (`id`) on update cascade;');

    this.addSql('alter table `file` add constraint `file_revision_id_foreign` foreign key (`revision_id`) references `revision` (`id`) on update cascade;');

    this.addSql('alter table `comment` add constraint `comment_revision_id_foreign` foreign key (`revision_id`) references `revision` (`id`) on update cascade;');
  }

}
