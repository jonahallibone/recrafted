import { Recording } from "entities/Recording";
import startOrm from "config/initalize-database";

export default async function getUploadUrl(req, res) {
  if (req.method === "GET") {
    const {
      query: { vid },
    } = req;

    const orm = await startOrm();
    const recording = await orm.em.findOne(Recording, { filename: vid });

    if (recording) {
      res.json({ recording });
    } else {
      res.status(405);
      res.end();
    }
  }
}
