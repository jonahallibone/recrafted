import "reflect-metadata";
import auth0 from "config/auth0";
import Prisma from "config/prisma";

export default auth0.requireAuthentication(async (req, res) => {
  if (req.method === "PUT") {
    const {
      query: { revisionId },
      body: { newComment },
    } = req;

    const session = await auth0.getSession(req);
    const { user: sessionUser } = session;

    try {
      const comment = await Prisma.revision.update({
        where: {
          id: Number(revisionId),
        },
        data: {
          comments: {
            create: {
              author: {
                connect: {
                  email: sessionUser.email,
                },
              },
              description: newComment.description,
              is_annotation: false,
            },
          },
        },
        include: {
          comments: {
            include: {
              author: true,
            },
            orderBy: { created_at: "desc" },
          },
        },
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
