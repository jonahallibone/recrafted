import "reflect-metadata";
import startOrm from "config/initalize-database";
import { Asset } from "entities/Asset";
import auth0 from "config/auth0.js";
import { QueryOrder } from "@mikro-orm/core";

export default auth0.requireAuthentication(async (req, res) => {
  if (req.method === "GET") {
    const {
      query: { assetId },
    } = req;

    const session = await auth0.getSession(req);
    const { user: sessionUser } = session;

    const orm = await startOrm();

    const asset = await orm.em.findOne(
      Asset,
      {
        id: assetId,
        project: { users: { user: { email: sessionUser.email } } },
      },
      ["revisions.files"]
    );

    res.end(JSON.stringify({ asset }));
  }
});
