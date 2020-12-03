import { Entity, ManyToOne, OneToOne, Property } from "@mikro-orm/core";
import { BaseEntity } from "./BaseEntity";
import { Project } from "./Project";
import { User } from "./User";

@Entity()
export class UserProject extends BaseEntity {
  @ManyToOne({ nullable: true })
  user: User;

  @ManyToOne({ nullable: true })
  project: Project;

  @Property({ onCreate: () => 1 })
  is_active: boolean;

  @Property({ onCreate: () => 0 })
  is_author: boolean;

  constructor() {
    super();
  }
}
