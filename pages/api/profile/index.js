
import "reflect-metadata";
import startOrm from "config/initalize-database";
import { User } from "entities/User";

export default async (req, res) => {
  if (req.method === "POST") {
    const {
      body: { email },
    } = req;

    console.log(email);

    const orm = await startOrm();
    const users = await orm.em.findOne(User, { email });

    res.statusCode = 200;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ users }));
  } else {
    res.status(405);
    res.end();
  }
};
