import "reflect-metadata";
import { QueryOrder } from "@mikro-orm/core";
import startOrm from "config/initalize-database";
import auth0 from "config/auth0";
import { UserProject } from "entities/UserProject";

export default auth0.requireAuthentication(async (req, res) => {
  if (req.method === "GET") {
    const orm = await startOrm();

    const session = await auth0.getSession(req);
    const { user: sessionUser } = session;

    const projects = await orm.em.find(
      UserProject,
      { user: { email: sessionUser.email } },
      ["user", "project", "project.users", "project.assets"],
      { createdAt: QueryOrder.DESC }
    );

    res.end(JSON.stringify({ projects }));
  } else {
    res.status(405);
    res.end();
  }
});
