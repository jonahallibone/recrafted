import "reflect-metadata";
import startOrm from "config/initalize-database";
import { UserProject } from "entities/UserProject";
import auth0 from "config/auth0.js";
import { QueryOrder } from "@mikro-orm/core";

export default auth0.requireAuthentication(async (req, res) => {
  if (req.method === "GET") {
    const {
      query: { projectId },
    } = req;

    const orm = await startOrm();

    const userProject = await orm.em.findOne(
      UserProject,
      { project: projectId },
      ["user", "project.assets.revisions.files", "project.users"],
      { project: { assets: { createdAt: QueryOrder.DESC } } }
    );

    res.end(JSON.stringify({ userProject }));
  }
});
