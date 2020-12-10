import auth0 from "config/auth0";
import Prisma from "config/prisma";

export default auth0.requireAuthentication(async (req, res) => {
  if (req.method === "GET") {
    const {
      query: { assetId },
    } = req;

    const session = await auth0.getSession(req);
    const { user: sessionUser } = session;

    const asset = await Prisma.asset.findFirst({
      where: {
        id: Number(assetId),
        project: {
          user_projects: { some: { user: { email: sessionUser.email } } },
        },
      },
      include: {
        revisions: {
          include: {
            files: true,
          },
        },
      },
    });

    res.end(JSON.stringify({ asset }));
  }
});
