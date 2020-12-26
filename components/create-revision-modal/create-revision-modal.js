import React, { useState, useCallback } from "react";
import {
  Modal,
  ModalOverlay,
  ModalContent,
  ModalCloseButton,
  Container,
  Stack,
  Heading,
  Button,
  Box,
  Image,
} from "@chakra-ui/react";
import { useDropzone } from "react-dropzone";
import Link from "next/link";
import uploadNewAsset, { uploadFile } from "utils/upload-new-asset";
import { ArrowRight } from "react-feather";
import { mutate } from "swr";

const CreateRevisionModal = ({
  onClose,
  isOpen,
  assetId,
  assetName,
  projectId,
}) => {
  const [revisionFile, setRevisionFile] = useState({
    file: null,
    previewURL: null,
  });
  const [uploadState, setUploadState] = useState({});
  const [newRevision, setNewRevision] = useState(null);

  const onDrop = (acceptedFiles) => {
    const [file] = acceptedFiles;
    setRevisionFile({ file, previewURL: URL.createObjectURL(file) });
  };
  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: false,
  });

  const handleUploadChange = useCallback(({ prevState, progress, size }) => {
    const percentage = Math.round((progress / size) * 100);

    if (percentage < 100) {
      return { ...prevState, progress: percentage, isUploading: true };
    }

    return { ...prevState, progress: percentage, isUploading: true };
  }, []);

  const uploadRevision = async () => {
    const { file } = revisionFile;

    try {
      setUploadState((state) => ({ ...state, status: "Preparing..." }));
      const { uploadURL, createdAsset, fileKey } = await uploadNewAsset({
        url: `/api/project/${projectId}/asset/${assetId}/revision/create`,
        assetId,
        file: { file },
        requestKey: "revision",
      });

      setNewRevision(createdAsset);

      mutate(`/api/project/${projectId}/asset/${assetId}`, (data) => ({
        ...data,
        asset: {
          ...data.asset,
          revisions: [...data.asset.revisions],
        },
      }));

      const { size } = file;

      await uploadFile({
        uploadURL,
        file,
        fileKey,
        // Get the last item in the revisions array to convert the files
        revisionId: createdAsset.revisions[0].id,
        onProgressChange: (progress) =>
          setUploadState((state) => ({
            status: "Uploading",
            ...handleUploadChange({
              ...state,
              progress,
              size,
            }),
          })),
      });
    } catch (error) {
      console.error(error);
      setUploadState((state) => ({ ...state, status: "Error" }));
    } finally {
      setUploadState((state) => ({ ...state, status: "Done" }));
    }
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose}>
      <ModalOverlay />
      <ModalContent maxW="100vw" h="100vh" m="0" rounded="none">
        <ModalCloseButton />
        <Container maxW="xl">
          <Stack h="100vh" align="center" justify="center">
            <Heading size="lg" fontWeight="medium" mb="8">
              Add New Revision to {assetName}
            </Heading>
            {!revisionFile.previewURL && (
              <Box {...getRootProps()} w="700px">
                <Box
                  rounded="xl"
                  w="100%"
                  as={Stack}
                  align="center"
                  justify="center"
                  minH="500px"
                  border="2px dashed"
                  borderColor={isDragActive ? "blue.200" : "gray.200"}
                  bg={isDragActive ? "blue.50" : "gray.50"}
                >
                  <Box as="input" visibility="hidden" {...getInputProps()} />
                  <Heading size="md">
                    Drop New Revision here or Click to Browse
                  </Heading>
                </Box>
              </Box>
            )}
            {revisionFile.previewURL && (
              <Box
                p="4"
                border="1px solid"
                borderColor="gray.200"
                rounded="md"
                maxW="lg"
              >
                <Image src={revisionFile.previewURL} />
              </Box>
            )}
            {uploadState.status !== "Done" && (
              <Button
                colorScheme="teal"
                onClick={uploadRevision}
                disabled={uploadState?.status}
              >
                {!uploadState?.status
                  ? "Create New Revision"
                  : `${uploadState.status} ${uploadState.progress || ""}%`}
              </Button>
            )}
            {uploadState.status === "Done" && (
              <Link
                href={`/project/${projectId}/asset/${assetId}/version/${newRevision.revisions[0].version}`}
              >
                <Button
                  rightIcon={<ArrowRight />}
                  as="a"
                  colorScheme="blue"
                  cursor="pointer"
                  onClick={onClose}
                >
                  Go to new version
                </Button>
              </Link>
            )}
          </Stack>
        </Container>
      </ModalContent>
    </Modal>
  );
};

export default CreateRevisionModal;
