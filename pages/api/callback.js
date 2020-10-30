import "reflect-metadata";
import auth0 from "../../config/auth0";
import startOrm from "../../config/initalize-database";
import { User } from "../../entities/User";

export default async function callback(req, res) {
  try {
    await auth0.handleCallback(req, res, {
      onUserLoaded: async (req, res, session, state) => {
        const orm = await startOrm();
        const userExists = await orm.em.findOne(User, {
          sub: session.user.sub,
        });
        console.log(userExists);

        if (!userExists) {
          const user = new User(
            session.user.name,
            session.user.email,
            session.user.sub
          );
          await orm.em.persistAndFlush([user]);
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
