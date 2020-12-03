import {
  Collection,
  Entity,
  OneToMany,
  Property,
  Unique,
  Cascade,
  ManyToMany,
} from "@mikro-orm/core";
import { BaseEntity } from "./BaseEntity";import { Project } from "./Project";
;
import { UserProject } from "./UserProject";

@Entity()
export class User extends BaseEntity {
  @Property()
  name!: string;

  @Property({ nullable: false })
  @Unique()
  sub!: string;

  @Property()
  @Unique()
  email: string;

  @OneToMany({
    entity: () => "UserProject", 
    mappedBy: 'user', //FK of the user
    cascade: [Cascade.PERSIST, Cascade.MERGE],
  })
  projects = new Collection<UserProject>(this);

  constructor(name: string, email: string, sub: string) {
    super();
    this.name = name;
    this.email = email;
    this.sub = sub;
  }
}
