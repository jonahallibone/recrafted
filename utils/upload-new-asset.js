import axios from "axios";
import fetcher from "utils/fetcher";
import { mutate } from "swr";

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

  return { file, createdAsset, uploadURL };
};

const uploadFile = async ({
  file,
  uploadURL,
  onProgressChange = () => {},
  onError = () => {},
  onSuccess = () => {},
}) => {
  try {
    await axios.put(uploadURL, file, {
      headers: { "Content-Type": file.type },
      onUploadProgress: (progressEvent) =>
        onProgressChange(progressEvent.loaded),
    });
  } catch (error) {
    console.error(error);
  }
};

export { uploadNewAsset as default, uploadFile };
