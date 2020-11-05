import AWS from "aws-sdk";
import { Recording } from "entities/Recording";
import startOrm from "config/initalize-database";
import { v4 as uuidv4 } from "uuid";
import { customAlphabet, urlAlphabet } from "nanoid";

export default async function getUploadUrl(req, res) {
  try {
    AWS.config.update({
      accessKeyId: process.env.NEXT_AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.NEXT_AWS_SECRET_ACCESS_KEY,
      region: process.env.NEXT_AWS_REGION,
    });

    const URL_EXPIRATION_SECONDS = 300;

    const s3 = new AWS.S3();
    const randomID = uuidv4();
    const Key = `${randomID}.webm`;

    const s3Params = {
      Bucket: process.env.UPLOAD_BUCKET,
      Key,
      Expires: URL_EXPIRATION_SECONDS,
      ContentType: "video/webm",
    };

    const orm = await startOrm();
    const nanoid = customAlphabet(urlAlphabet, 10);
    const shortID = nanoid();
    const recording = new Recording(shortID, Key);


    await orm.em.persistAndFlush([recording]);

    const uploadURL = await s3.getSignedUrlPromise("putObject", s3Params);
    return res.json({
      uploadURL,
      shortID
    });
  } catch (error) {
    console.error(error);
    return res.status(error.status || 400).end(error.message);
  }
}
