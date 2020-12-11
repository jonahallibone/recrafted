import "reflect-metadata";
import auth0 from "config/auth0";
import Prisma from "config/prisma";

export default async function callback(req, res) {
  try {
    await auth0.handleCallback(req, res, {
      onUserLoaded: async (req, res, session, state) => {
        const userExists = await Prisma.user.findFirst({
          where: {
            sub: session.user.sub,
          },
        });

        if (!userExists) {
          await Prisma.user.create({
            data: {
              name: session.user.name,
              email: session.user.email,
              sub: session.user.sub,
            },
          });
        }

        return userExists
          ? {
              ...session,
              user: { ...session.user, is_admin: userExists.is_admin },
            }
          : { ...session };
      },
      redirectTo: "/",
    });
  } catch (error) {
    console.error(error);
    res.status(error.status || 400).end(error.message);
  }
}
