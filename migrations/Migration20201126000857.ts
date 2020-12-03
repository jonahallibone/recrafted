import { Migration } from '@mikro-orm/migrations';

export class Migration20201126000857 extends Migration {

  async up(): Promise<void> {
    this.addSql('alter table `project` add `thumbnail_color` varchar(255) default "green.500" not null;');
  }

}
