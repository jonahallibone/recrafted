import React, { useCallback, useEffect, useState } from "react";
import NextLink from "next/link";
import Image from "next/image";
import {
  AspectRatio,
  Badge,
  Box,
  CircularProgress,
  CircularProgressLabel,
  Heading,
  Skeleton,
  Stack,
} from "@chakra-ui/react";
import { uploadFile } from "utils/upload-new-asset";

const FileCard = ({ isLoading, asset, projectId }) => {
  const [uploadState, setUploadState] = useState({});

  function offsetUploadFinish() {
    const promise = new Promise((resolve, reject) => {
      window.setTimeout(() => {
        setUploadState((state) => ({ ...state, isUploading: false }), 500);
        resolve();
      }, 500);
    });
    return promise;
  }

  const handleUploadChange = useCallback(({ prevState, progress, size }) => {
    const percentage = Math.round((progress / size) * 100);
    if (percentage < 100) {
      return { ...prevState, progress: percentage, isUploading: true };
    }

    offsetUploadFinish();
    return { ...prevState, progress: percentage, isUploading: true };
  }, []);

  useEffect(() => {
    if (asset?.isReadyToUpload) {
      const { size } = asset.file;
      uploadFile({
        uploadURL: asset.uploadURL,
        file: asset.file,
        onProgressChange: (progress) =>
          setUploadState((state) =>
            handleUploadChange({ ...state, progress, size })
          ),
      });
    }
  }, [asset, handleUploadChange]);

  if (isLoading) {
    return (
      <Box p="4" border="1px solid" borderColor="gray.200" rounded="md">
        <AspectRatio ratio={4 / 3} position="relative">
          <Skeleton height="100%" position="absolute" rounded="md" />
        </AspectRatio>
        <Box>
          <Skeleton height="20px" rounded="md" mt="4" />
          <Skeleton height="20px" rounded="md" mt="4" width="70%" />
        </Box>
      </Box>
    );
  }

  return (
    <NextLink href={`/project/${projectId}/asset/${asset.id}`}>
      <Stack
        as="a"
        cursor="pointer"
        border="1px solid"
        borderColor="gray.200"
        rounded="md"
      >
        <Box p="4">
          <AspectRatio ratio={4 / 3} position="relative">
            <Box height="100%" position="absolute" rounded="md" bg="gray.100">
              {!uploadState.isUploading && (
                <Image
                  // unoptimized
                  src={`https://d2iutcxiokgxnt.cloudfront.net/${asset.revisions[0]?.files[0]?.src}`}
                  height={500}
                  width={500}
                  layout="intrinsic"
                />
              )}
              {uploadState.isUploading && (
                <CircularProgress
                  thickness="4px"
                  size="60px"
                  color="purple.500"
                  value={uploadState.progress}
                >
                  <CircularProgressLabel>
                    {uploadState.progress}%
                  </CircularProgressLabel>
                </CircularProgress>
              )}
            </Box>
          </AspectRatio>
        </Box>
        <Box
          p="4"
          mt="0"
          borderTop="1px solid"
          borderColor="gray.200"
          bg="gray.50"
          h="100%"
          roundedBottom="md"
        >
          <Heading size="sm" fontWeight="500">
            {asset.name}
          </Heading>
          <Badge size="xs" mt="2" fontWeight="500" colorScheme="purple">
            {asset.type}
          </Badge>
        </Box>
      </Stack>
    </NextLink>
  );
};

export default FileCard;
