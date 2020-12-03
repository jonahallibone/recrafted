import {
  Entity,
  Property,
  OneToMany,
  Cascade,
  Collection,
  ManyToOne,
} from "@mikro-orm/core";
import { BaseEntity } from "./BaseEntity";
import { Project } from "./Project";
import { Revision } from "./Revision";

@Entity()
export class Asset extends BaseEntity {
  @Property({ nullable: false })
  type!: string;

  @Property({ nullable: false })
  status!: string;

  @Property({ nullable: false })
  name!: string;

  @ManyToOne({ nullable: false })
  project: Project;

  @OneToMany({
    entity: () => "Revision",
    mappedBy: "asset", //FK of the revision
    cascade: [Cascade.PERSIST, Cascade.MERGE],
  })
  revisions = new Collection<Revision>(this);

  constructor({ status, type, name }) {
    super();
    this.status = status;
    this.type = type;
    this.name = name;
  }
}
