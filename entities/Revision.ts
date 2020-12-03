import {
  Entity,
  Property,
  OneToMany,
  Cascade,
  Collection,
  ManyToOne,
} from "@mikro-orm/core";
import { Asset } from "./Asset";
import { BaseEntity } from "./BaseEntity";
import { File } from "./File";

@Entity()
export class Revision extends BaseEntity {
  @Property({ nullable: false })
  version!: number;

  @ManyToOne({ nullable: false })
  asset: Asset;

  @OneToMany({
    entity: () => "Comment",
    mappedBy: "revision", //FK of the project
    cascade: [Cascade.PERSIST, Cascade.MERGE],
  })
  revisions = new Collection<Comment>(this);

  @OneToMany({
    entity: () => "File",
    mappedBy: "revision", //FK of the file
    cascade: [Cascade.PERSIST, Cascade.MERGE],
  })
  files = new Collection<File>(this);

  constructor(version: number) {
    super();
    this.version = version;
  }
}
