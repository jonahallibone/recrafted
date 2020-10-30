import { User } from "../entities/User";
import { Options } from "@mikro-orm/core";
import dotenv from "dotenv";
import { BaseEntity } from "../entities/BaseEntity";
import { Recording } from "../entities/Recording";
dotenv.config();

const config: Options = {
  dbName: process.env.MYSQL_DATABASE,
  type: "mysql",
  host: process.env.MYSQL_HOST,
  port: Number(process.env.MYSQL_PORT),
  user: process.env.MYSQL_USERNAME,
  password: process.env.MYSQL_PASSWORD,
  entities: [BaseEntity, User, Recording],
  discovery: { disableDynamicFileAccess: false },
  debug: process.env.NODE_ENV === "development",
};
export default config;
