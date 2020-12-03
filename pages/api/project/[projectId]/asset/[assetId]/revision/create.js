import "reflect-metadata";
import { v4 as uuidv4 } from "uuid";
import AWS from "aws-sdk";
import startOrm from "config/initalize-database";
import auth0 from "config/auth0";
import { UserProject } from "entities/UserProject";
import { Asset } from "entities/Asset";
import { Revision } from "entities/Revision";
import { File } from "entities/File";

export default auth0.requireAuthentication(async (req, res) => {
  if (req.method === "PUT") {
    const {
      query: { assetId },
      body: { revision },
    } = req;

    const orm = await startOrm();

    const session = await auth0.getSession(req);
    const { user: sessionUser } = session;

    const asset = await orm.em.findOne(
      Asset,
      {
        id: assetId,
        project: { users: { user: { email: sessionUser.email } } },
      },
      ["revisions.files"]
    );

    if (asset) {
      AWS.config.update({
        accessKeyId: process.env.NEXT_AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.NEXT_AWS_SECRET_ACCESS_KEY,
        region: process.env.NEXT_AWS_REGION,
      });

      const URL_EXPIRATION_SECONDS = 300;

      const s3 = new AWS.S3();
      const randomID = uuidv4();
      const fileKey = `${randomID}.${asset.fileExtension}`;

      const s3Params = {
        Bucket: process.env.UPLOAD_BUCKET,
        Key: fileKey,
        Expires: URL_EXPIRATION_SECONDS,
        ContentType: revision.mimeType,
      };

      const versionNumber = asset.revisions.length;

      const firstRevision = new Revision(versionNumber);
      const newFile = new File({
        src: fileKey,
        mime_type: revision.mimeType,
        file_size: revision.fileSize,
        is_original: revision.isOriginal,
        file_extension: revision.fileExtension,
        height: revision.height,
        width: revision.width,
      });

      asset.revisions.add(firstRevision);
      firstRevision.files.add(newFile);

      await orm.em.persistAndFlush([asset]);

      const uploadURL = await s3.getSignedUrlPromise("putObject", s3Params);

      const createdAsset = await orm.em.findOne(Asset, { id: asset.id }, [
        "revisions.files",
      ]);

      return res.end(JSON.stringify({ createdAsset, fileKey, uploadURL }));
    }

    res.status(405);
    res.end();
  } else {
    res.status(405);
    res.end();
  }
});
