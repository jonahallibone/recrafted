import axios from "axios";
import fetcher from "utils/fetcher";

function getFileExtension(filename) {
  // eslint-disable-next-line no-bitwise
  return filename.slice(((filename.lastIndexOf(".") - 1) >>> 0) + 2);
}

const uploadNewAsset = async ({ url = "", file, requestKey }) => {
  const { createdAsset, fileKey, uploadURL } = await fetcher(url, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      [`${requestKey}`]: {
        name: file.file.name,
        mimeType: file.file.type,
        fileExtension: getFileExtension(file.file.name),
        fileSize: file.file.size,
        isOriginal: true,
        height: 100,
        width: 100,
      },
    }),
  });

  return { file, createdAsset, uploadURL, fileKey };
};

const uploadFile = async ({
  file,
  uploadURL,
  fileKey,
  revisionId,
  onProgressChange = () => {},
  onError = (error) => {
    console.error(error);
  },
  onSuccess = (success) => success,
}) => {
  try {
    await axios.put(uploadURL, file, {
      headers: { "Content-Type": file.type },
      onUploadProgress: (progressEvent) =>
        onProgressChange(progressEvent.loaded),
    });

    const { files } = await fetcher("/api/generate", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        fileKey,
        revisionId,
      }),
    });

    onSuccess({ files });

    return { files };
  } catch (error) {
    onError(error);
    return { error };
  }
};

export { uploadNewAsset as default, uploadFile };
