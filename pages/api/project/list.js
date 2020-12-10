import auth0 from "config/auth0";
import Prisma from "config/prisma";

export default auth0.requireAuthentication(async (req, res) => {
  if (req.method === "GET") {

    const session = await auth0.getSession(req);
    const { user: sessionUser } = session;

    const projects = await Prisma.user_project.findMany({
      orderBy: { updated_at: "desc" },
      where: { user: { email: sessionUser.email } },
      include: {
        user: true,
        project: {
          include: {
            user_projects: { include: { user: true } },
            assets: true,
          },
        },
      },
    });

    res.end(JSON.stringify({ projects }));
  } else {
    res.status(405);
    res.end();
  }
});
