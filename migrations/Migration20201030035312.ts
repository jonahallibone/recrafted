import { Migration } from '@mikro-orm/migrations';

export class Migration20201030035312 extends Migration {

  async up(): Promise<void> {
    this.addSql('create table `user` (`id` int unsigned not null auto_increment primary key, `created_at` datetime not null, `updated_at` datetime not null, `name` varchar(255) not null, `sub` varchar(255) not null, `email` varchar(255) not null) default character set utf8mb4 engine = InnoDB;');
    this.addSql('alter table `user` add unique `user_sub_unique`(`sub`);');
    this.addSql('alter table `user` add unique `user_email_unique`(`email`);');

    this.addSql('create table `recording` (`id` int unsigned not null auto_increment primary key, `created_at` datetime not null, `updated_at` datetime not null, `filename` varchar(255) not null, `s3_ref` varchar(255) not null, `user_id` int(11) unsigned null) default character set utf8mb4 engine = InnoDB;');
    this.addSql('alter table `recording` add index `recording_user_id_index`(`user_id`);');

    this.addSql('create table `base_entity` (`id` int unsigned not null auto_increment primary key, `created_at` datetime not null, `updated_at` datetime not null) default character set utf8mb4 engine = InnoDB;');

    this.addSql('alter table `recording` add constraint `recording_user_id_foreign` foreign key (`user_id`) references `user` (`id`) on update cascade on delete set null;');
  }

}
