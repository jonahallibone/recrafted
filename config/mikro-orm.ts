import { User } from "../entities/User";
import { Options } from "@mikro-orm/core";
import dotenv from "dotenv";
import { BaseEntity } from "../entities/BaseEntity";
import { Project } from "../entities/Project";
import { Revision } from "../entities/Revision";
import { File } from "../entities/File";
import { UserProject } from "../entities/UserProject";
import { Asset } from "../entities/Asset";
import { Comment } from "../entities/Comment";

dotenv.config({
  path:
    process.env.NODE_ENV === "development" ? ".env" : ".env.production.local",
});

const config: Options = {
  dbName: process.env.MYSQL_DATABASE,
  type: "mysql",
  host: process.env.MYSQL_HOST,
  port: Number(process.env.MYSQL_PORT),
  user: process.env.MYSQL_USERNAME,
  password: process.env.MYSQL_PASSWORD,
  entities: [BaseEntity, Project, User, Revision, File, Comment, UserProject, Asset],
  discovery: { disableDynamicFileAccess: false },
  debug: process.env.NODE_ENV === "development",
};
export default config;
