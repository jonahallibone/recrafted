import {
  Entity,
  Property,
  ManyToOne,
} from "@mikro-orm/core";
import { BaseEntity } from "./BaseEntity";
import { Revision } from "./Revision";
import { User } from "./User";

@Entity()
export class Comment extends BaseEntity {
  @Property({ nullable: false })
  description!: string;

  @Property({ nullable: true })
  x_coordinate: number;

  @Property({ nullable: false })
  y_coordinate: number;

  @Property({ onCreate: () => 0 })
  is_annotation: boolean;

  @Property({ nullable: false })
  author: User;

  @ManyToOne({ nullable: false })
  revision: Revision;

  constructor(description: string) {
    super();
    this.description = description;
  }
}
