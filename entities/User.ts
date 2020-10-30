import {
  Collection,
  Entity,
  OneToMany,
  Property,
  Unique,
  Cascade,
} from "@mikro-orm/core";
import { BaseEntity } from "./BaseEntity";
import { Recording } from "./Recording";

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
    entity: () => "Recording",
    mappedBy: "user",
    cascade: [Cascade.PERSIST, Cascade.MERGE],
  })
  recordings = new Collection<Recording>(this);

  constructor(name: string, email: string, sub: string) {
    super();
    this.name = name;
    this.email = email;
    this.sub = sub;
  }
}
