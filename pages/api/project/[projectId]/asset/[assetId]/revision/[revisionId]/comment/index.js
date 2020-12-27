import "reflect-metadata";
import auth0 from "config/auth0";
import Prisma from "config/prisma";

export default auth0.requireAuthentication(async (req, res) => {
  if (req.method === "GET") {
    const {
      query: { revisionId },
    } = req;

    const session = await auth0.getSession(req);
    const { user: sessionUser } = session;

    try {
      const comment = await Prisma.comment.findMany({
        where: {
          revision_id: Number(revisionId),
        },
        include: {
          author: true,
        },
        orderBy: { created_at: "desc" },
      });

      res.status(200).json(comment);
    } catch (error) {
      console.error(error);
      res.status(500).json(error);
    }
  } else {
    res.status(405).end();
  }
});
