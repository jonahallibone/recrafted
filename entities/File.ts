import { Entity, Property, ManyToOne } from "@mikro-orm/core";
import { BaseEntity } from "./BaseEntity";
import { Revision } from "./Revision";

@Entity()
export class File extends BaseEntity {
  @Property({ nullable: false })
  src: string;

  @Property({ onCreate: () => 0 })
  is_original: boolean;

  @Property({ nullable: false })
  file_size: number;

  @Property({ nullable: false })
  mime_type: string;

  @Property({ nullable: false })
  file_extension: string;

  @Property({ nullable: true })
  height: number;

  @Property({ nullable: true })
  width: number;

  @ManyToOne({ nullable: false })
  revision: Revision;

  constructor({
    src,
    mime_type,
    file_size,
    is_original,
    file_extension,
    height,
    width,
  }) {
    super();
    this.src = src;
    this.mime_type = mime_type;
    this.file_size = file_size;
    this.is_original = is_original;
    this.file_extension = file_extension;
    this.height = height;
    this.width = width;
  }
}
