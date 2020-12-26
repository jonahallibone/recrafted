import React, { useCallback, useState } from "react";
import { useRouter } from "next/router";
import Layout from "components/layout/layout";
import {
  Box,
  Button,
  Container,
  Flex,
  Heading,
  IconButton,
  SimpleGrid,
  Stack,
} from "@chakra-ui/react";
import useSWR, { mutate } from "swr";
import fetcher from "utils/fetcher";
import uploadNewAsset from "utils/upload-new-asset";
import FileCard from "components/file-card/file-card";
import { useDropzone } from "react-dropzone";
import { MoreHorizontal, Upload, UserPlus } from "react-feather";

const Project = () => {
  const router = useRouter();
  const { projectId } = router.query;
  const { data, error } = useSWR(`/api/project/${projectId}`, fetcher);

  const onDrop = useCallback(
    (acceptedFiles) => {
      const fileObjects = acceptedFiles.map((file) => ({
        file,
        progress: 0,
        status: "Starting",
      }));

      fileObjects.forEach(async (file) => {
        const {
          file: uploadFile,
          createdAsset,
          uploadURL,
          fileKey,
        } = await uploadNewAsset({
          url: `/api/project/${projectId}/asset/create`,
          projectId,
          file,
          requestKey: "asset",
        });

        mutate(`/api/project/${projectId}`, (prevData) => ({
          ...prevData,
          userProject: {
            ...prevData.userProject,
            project: {
              ...prevData.userProject.project,
              assets: [
                {
                  isReadyToUpload: true,
                  uploadURL,
                  file: uploadFile.file,
                  fileKey,
                  ...createdAsset,
                },
                ...prevData.userProject.project.assets,
              ],
            },
          },
        }));
      });
    },
    [projectId]
  );

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    noClick: true,
  });

  return (
    <Layout nopadding>
      <Box borderBottom="1px solid" borderColor="gray.200" py="3">
        <Container maxW="100%">
          <SimpleGrid columns="2" justify="center">
            <Box as={Flex} alignItems="center">
              <Heading size="md" fontWeight="bold">
                {data?.userProject?.project?.project_name}
              </Heading>
            </Box>
            <Stack direction="row" as={Flex} justifyContent="flex-end">
              <Button leftIcon={<UserPlus size="18px" />} colorScheme="purple">
                Share
              </Button>
              <Button leftIcon={<Upload size="18px" />} variant="solid">
                Upload
              </Button>{" "}
              <IconButton icon={<MoreHorizontal />} />
            </Stack>
          </SimpleGrid>
        </Container>
      </Box>
      <Container
        maxW="100%"
        pb="10"
        {...getRootProps()}
        _focus={{ outline: "none" }}
        bg={isDragActive && "blue.50"}
        transition="all 0.2s"
        minH="500px"
      >
        {isDragActive && (
          <Box
            position="fixed"
            h="calc(100vh - 57px)"
            w="100%"
            left="0"
            top="57px"
            zIndex="99"
            p="4"
          >
            <Box h="100%" w="100%" bg="rgba(83, 82, 237, 0.8)" rounded="xl">
              <Box
                position="absolute"
                top="50%"
                left="50%"
                transform="translate(-50%,-50%)"
              >
                <Heading color="white">Drop files to upload</Heading>
              </Box>
            </Box>
          </Box>
        )}
        {!data && (
          <SimpleGrid columns={[1, 2, 4]} gap={10}>
            <FileCard isLoading />
            <FileCard isLoading />
            <FileCard isLoading />
            <FileCard isLoading />
          </SimpleGrid>
        )}
        <Box as="input" visibility="hidden" {...getInputProps()} />
        <SimpleGrid mt="8" columns={[1, 2, 4]} gap={10}>
          {data &&
            !!data.userProject.project.assets.length &&
            data.userProject.project.assets.map((asset) => (
              <FileCard key={asset.id} asset={asset} projectId={projectId} />
            ))}
        </SimpleGrid>
      </Container>
    </Layout>
  );
};

export default Project;
