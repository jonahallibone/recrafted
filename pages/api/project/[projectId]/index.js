import auth0 from "config/auth0";
import Prisma from "config/prisma";

export default auth0.requireAuthentication(async (req, res) => {
  if (req.method === "GET") {
    const {
      query: { projectId },
    } = req;

    const userProject = await Prisma.user_project.findUnique({
      where: { project_id: Number(projectId) },
      include: {
        user: true,
        project: {
          include: {
            assets: {
              include: {
                revisions: {
                  include: {
                    files: true,
                  },
                },
              },
            },
            user_projects: true,
          },
        },
      },
    });

    res.end(JSON.stringify({ userProject }));
  }
});
