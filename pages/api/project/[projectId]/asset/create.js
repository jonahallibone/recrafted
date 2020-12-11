import { v4 as uuidv4 } from "uuid";
import AWS from "aws-sdk";
import auth0 from "config/auth0";
import Prisma from "config/prisma";

export default auth0.requireAuthentication(async (req, res) => {
  if (req.method === "PUT") {
    const {
      query: { projectId },
      body: { asset },
    } = req;

    const session = await auth0.getSession(req);
    const { user: sessionUser } = session;

    const userProject = await Prisma.user_project.findFirst({
      where: {
        project_id: Number(projectId),
        user: { email: sessionUser.email },
      },
      include: {
        user: true,
        project: {
          include: {
            assets: {
              include: {
                revisions: {
                  include: {
                    files: true,
                  },
                },
              },
            },
            user_projects: true,
          },
        },
      },
    });

    if (userProject) {
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
        ContentType: asset.mimeType,
      };

      const newAsset = await Prisma.asset.create({
        data: {
          project: {
            connect: {
              id: Number(projectId),
            },
          },
          name: asset.name,
          status: "Unapproved",
          type: asset.mimeType,
          revisions: {
            create: [
              {
                version: 1,
                files: {
                  create: [
                    {
                      src: fileKey,
                      mime_type: asset.mimeType,
                      file_size: asset.fileSize,
                      is_original: asset.isOriginal,
                      file_extension: asset.fileExtension,
                      height: asset.height,
                      width: asset.width,
                    },
                  ],
                },
              },
            ],
          },
        },
      });

      const createdAsset = await Prisma.asset.findFirst({
        where: {
          id: newAsset.id,
        },
        include: {
          project: {
            include: { user_projects: true },
          },
          revisions: {
            include: {
              files: true,
            },
          },
        },
      });

      const uploadURL = await s3.getSignedUrlPromise("putObject", s3Params);

      return res.end(JSON.stringify({ createdAsset, fileKey, uploadURL }));
    }

    res.status(405);
    res.end();
  } else {
    res.status(405);
    res.end();
  }
});
