import "reflect-metadata";
import { v4 as uuidv4 } from "uuid";
import AWS from "aws-sdk";
import auth0 from "config/auth0";
import Prisma from "config/prisma";

export default auth0.requireAuthentication(async (req, res) => {
  if (req.method === "PUT") {
    const {
      query: { assetId },
      body: { revision },
    } = req;

    const session = await auth0.getSession(req);
    const { user: sessionUser } = session;

    const asset = await Prisma.asset.findFirst({
      where: {
        id: Number(assetId),
        project: {
          user_projects: { some: { user: { email: sessionUser.email } } },
        },
      },
      include: {
        revisions: true,
      },
    });

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

      const versionNumber = asset.revisions.length + 1;

      const addNewRevisionToAsset = await Prisma.asset.update({
        where: {
          id: Number(assetId),
        },
        data: {
          revisions: {
            create: {
              version: versionNumber,
              files: {
                create: {
                  src: fileKey,
                  mime_type: revision.mimeType,
                  file_size: revision.fileSize,
                  is_original: revision.isOriginal,
                  file_extension: revision.fileExtension,
                  height: revision.height,
                  width: revision.width,
                },
              },
            },
          },
        },
        include: {
          revisions: {
            orderBy: { created_at: "desc" },
            take: 1,
          },
        },
      });

      try {
        const uploadURL = await s3.getSignedUrlPromise("putObject", s3Params);
        return res.end(
          JSON.stringify({
            createdAsset: addNewRevisionToAsset,
            fileKey,
            uploadURL,
          })
        );
      } catch (error) {
        console.error(error);
      }
    }

    res.status(405);
    res.end();
  } else {
    res.status(405);
    res.end();
  }
});
