import { PrimaryKey, Entity, Property, Type } from "@mikro-orm/core";

@Entity()
export class BaseEntity {
  @PrimaryKey()
  id!: number;

  @Property({ type: Date })
  createdAt = new Date();

  @Property({ type: Date, onUpdate: () => new Date() })
  updatedAt = new Date();
}
