import {
  Entity,
  ManyToOne,
  Property,
} from "@mikro-orm/core";
import { BaseEntity } from "./BaseEntity";
import { User } from "./User";

@Entity()
export class Recording extends BaseEntity {
  @Property({ nullable: false })
  filename!: string;

  @Property({ nullable: false })
  s3_ref!: string;

  @ManyToOne({ nullable: true })
  user: User;

  constructor(filename: string, s3_ref: string) {
    super();
    this.filename = filename;
    this.s3_ref = s3_ref;
  }
}
