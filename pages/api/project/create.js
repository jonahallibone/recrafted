import "reflect-metadata";
import startOrm from "config/initalize-database";
import auth0 from "config/auth0";
import { User } from "entities/User";
import { Project } from "entities/Project";
import { UserProject } from "entities/UserProject";

export default auth0.requireAuthentication(async (req, res) => {
  if (req.method === "PUT") {
    const {
      body: {
        projectDetails: { name, color },
      },
    } = req;

    const orm = await startOrm();

    const session = await auth0.getSession(req);
    const { user: sessionUser } = session;

    const user = await orm.em.findOne(User, { email: sessionUser.email });

    const project = new Project(name, color);
    const userProject = new UserProject();
    userProject.user = user;
    userProject.project = project;
    userProject.is_author = true;

    await orm.em.persistAndFlush([userProject]);

    await orm.em.findOne(UserProject, { id: userProject.id }, [
      "user",
      "project",
      "project.users",
      "project.assets",
    ]);

    res.end(JSON.stringify({ userProject }));
  } else {
    res.status(405);
    res.end();
  }
});
