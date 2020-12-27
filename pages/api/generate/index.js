import auth0 from "config/auth0";
import Prisma from "config/prisma";
import { v4 as uuidv4 } from "uuid";

export default auth0.requireAuthentication(async (req, res) => {
  if (req.method === "POST") {
    const {
      body: { revisionId, fileKey },
    } = req;

    const resp = await fetch(
      process.env.CONVERT_API_URL,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          key: fileKey,
          thumbnailS3Key: uuidv4(),
          convertedS3Key: uuidv4(),
        }),
      }
    );

    const { thumbnail, converted } = await resp.json();

    const addNewFileToRevision = await Prisma.revision.update({
      where: {
        id: Number(revisionId),
      },
      data: {
        files: {
          create: [
            {
              src: thumbnail.key,
              mime_type: thumbnail.mimeType,
              file_size: thumbnail.fileSize,
              is_original: false,
              file_extension: thumbnail.fileExtension,
              height: thumbnail.height,
              width: thumbnail.width,
              type: "thumbnail"
            },
            {
              src: converted.key,
              mime_type: converted.mimeType,
              file_size: converted.fileSize,
              is_original: false,
              file_extension: converted.fileExtension,
              height: converted.height,
              width: converted.width,
              type: "full"
            },
          ],
        },
      },
      include: {
        files: true,
        author: true
      },
    });

    return res.status(200).json(addNewFileToRevision);
  }

  return res.status(405).end();
});
