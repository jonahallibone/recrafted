import Prisma from "config/prisma";

export default async (req, res) => {
  if (req.method === "POST") {
    const {
      body: { email },
    } = req;

    console.log(email);

    const users = await Prisma.user.findFirst({
      where: {
        email
      },
    });

    res.statusCode = 200;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ users }));
  } else {
    res.status(405);
    res.end();
  }
};
