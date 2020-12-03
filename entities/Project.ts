import {
  Entity,
  Property,
  ManyToOne,
  OneToMany,
  Cascade,
  Collection,
} from "@mikro-orm/core";
import { Asset } from "./Asset";
import { BaseEntity } from "./BaseEntity";
import { UserProject } from "./UserProject";

@Entity()
export class Project extends BaseEntity {
  @Property({ nullable: false })
  project_name!: string;

  @OneToMany({
    entity: () => "UserProject",
    mappedBy: "project", //FK of the project
    cascade: [Cascade.PERSIST, Cascade.MERGE],
  })
  users = new Collection<UserProject>(this);

  @OneToMany({
    entity: () => "Asset",
    mappedBy: "project", //FK of the asset
    cascade: [Cascade.PERSIST, Cascade.MERGE],
  })
  assets = new Collection<Asset>(this);

  @Property({ nullable: false })
  thumbnail_color!: string;

  constructor(project_name: string, thumbnail_color: string) {
    super();
    this.project_name = project_name;
    this.thumbnail_color = thumbnail_color;
  }
}
