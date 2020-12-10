import auth0 from "config/auth0";
import Prisma from "config/prisma";

export default auth0.requireAuthentication(async (req, res) => {
  if (req.method === "PUT") {
    const {
      body: {
        projectDetails: { name, color },
      },
    } = req;

    const session = await auth0.getSession(req);
    const { user: sessionUser } = session;

    const newProject = await Prisma.user_project.create({
      data: {
        user: {
          connect: {
            email: sessionUser.email,
          },
        },
        project: {
          create: {
            project_name: name,
            thumbnail_color: color,
          },
        },
        is_author: true,
        is_active: true,
      },
    });

    const userProject = await Prisma.user_project.findFirst({
      where: { id: newProject.id },
      include: {
        project: {
          include: {
            user_projects: {
              include: {
                user: true
              }
            },
          }
        },
      },
    });

    res.end(JSON.stringify({ userProject }));
  } else {
    res.status(405);
    res.end();
  }
});
