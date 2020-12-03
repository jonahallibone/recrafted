import { Migration } from '@mikro-orm/migrations';

export class Migration20201128091458 extends Migration {

  async up(): Promise<void> {
    this.addSql('alter table `file` add `file_size` int not null;');
    this.addSql('alter table `file` add `mime_type` varchar(255) not null;');
    this.addSql('alter table `file` add `file_extension` varchar(255) not null;');
    this.addSql('alter table `file` add `height` int default null;');
    this.addSql('alter table `file` add `width` int default null;');
  }
}
