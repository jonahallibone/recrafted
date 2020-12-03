import { Migration } from '@mikro-orm/migrations';

export class Migration20201129073400 extends Migration {

  async up(): Promise<void> {
    this.addSql('alter table `asset` add `name` varchar(255) not null;');
  }

}
