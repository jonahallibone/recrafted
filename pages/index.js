/* eslint-disable jsx-a11y/media-has-caption */
import React, { useRef, useState } from "react";
import Head from "next/head";
import {
  AspectRatioBox,
  Box,
  Button,
  Flex,
  Heading,
  Icon,
  Input,
  Spinner,
  Stack,
  Text,
  useClipboard,
} from "@chakra-ui/core";
import Layout from "components/layout/layout";
import Container from "components/container/container";
import BrowserConfetti from "components/confetti/confetti";
import CopyLink from "../components/copy-link/copy-link";

const MIME_TYPE = "video/webm";

export default function Home() {
  const videoPlayer = useRef(null);
  const finalBlob = useRef(null);
  const key = useRef(null);
  const [blobReady, setBlobReady] = useState();
  const [uploading, setUploading] = useState(false);
  const [uploadSuccessful, setUploadSuccessful] = useState({
    confettiOpen: false,
    videoUrl: "",
    uploadState: "inactive",
  });
  const [isVideoOpen, setIsVideoOpen] = useState(false);

  const getUploadURL = async () => {
    const req = await fetch("/api/aws/get-upload-url");
    return req.json();
  };

  const uploadVideo = async () => {
    try {
      setUploading(true);
      const { uploadURL, shortID } = await getUploadURL();
      key.current = shortID;
      await fetch(uploadURL, {
        method: "PUT",
        body: finalBlob.current,
      });
    } catch (error) {
      console.error(error);
    } finally {
      setUploading(false);
      setUploadSuccessful({
        confettiOpen: true,
        videoUrl:
          process.env.NODE_ENV === "development"
            ? `http://localhost:3000/v/${key.current}`
            : `https://tabgrab.app/v/${key.current}`,
        uploadState: "complete",
      });
    }
  };

  const handleStreamEnd = (streamBlob) => {
    videoPlayer.current.srcObject = null;
    videoPlayer.current.src = streamBlob;
    setBlobReady(true);
    setUploadSuccessful({ ...uploadSuccessful, uploadState: "pending" });
  };

  const handleRecording = (stream) => {
    const streamChunks = [];

    try {
      const recorder = new MediaRecorder(stream, { mimeType: MIME_TYPE });

      recorder.start();
      recorder.ondataavailable = ({ data }) => streamChunks.push(data);
      recorder.onstop = () => {
        finalBlob.current = new Blob(streamChunks, { type: MIME_TYPE });
        const streamBlob = URL.createObjectURL(finalBlob.current);
        handleStreamEnd(streamBlob);
      };
    } catch (err) {
      console.error(`Error: ${err}`);
    }
  };

  const chooseTabToRecord = async () => {
    let captureStream = null;

    try {
      captureStream = await navigator.mediaDevices.getDisplayMedia({
        video: true,
        audio: true,
      });
      videoPlayer.current.srcObject = captureStream;
      setIsVideoOpen(true);

      handleRecording(captureStream);
    } catch (err) {
      console.error(`Error: ${err}`);
    }
  };

  return (
    <Layout>
      <Head>
        <title>TabGrab | Share a Screen Recording</title>
        <link rel="icon" href="/favicon.ico" />
      </Head>
      {uploadSuccessful.confettiOpen && (
        <BrowserConfetti
          handleEnd={() =>
            setUploadSuccessful({ ...uploadSuccessful, confettiOpen: false })
          }
        />
      )}
      <Container>
        <Box
          as={Flex}
          minH="400px"
          h="25vw"
          alignItems="center"
          justifyContent="center"
          flexDirection="column"
        >
          <Flex justifyContent="center">
            <Heading
              textAlign="center"
              size="2xl"
              w={["100%", "80%", "65%"]}
              my="4"
              fontWeight="bold"
            >
              Record your desktop, tab or window and share in{" "}
              <Text display="inline" bg="yellow.100" px="2">
                seconds
              </Text>
            </Heading>
          </Flex>
          <Flex justifyContent="center" my="4">
            <Button onClick={chooseTabToRecord} size="lg" variantColor="cyan">
              Create New Recording
            </Button>
          </Flex>
        </Box>
        <Flex justifyContent="center">
          <AspectRatioBox ratio={16 / 9} minW="300px" w="100%" maxW="600px">
            <Box
              w="100%"
              h="100%"
              p="4"
              border="1px solid"
              borderColor="gray.200"
              rounded="md"
            >
              <Box
                display={isVideoOpen ? "block" : "none"}
                as="video"
                w="100%"
                h="100%"
                bg="black"
                ref={videoPlayer}
                autoPlay
                playsInline
                controls
              />
              {!isVideoOpen && (
                <Box
                  as={Flex}
                  justifyContent="center"
                  alignItems="center"
                  h="100%"
                  w="100%"
                  bg="gray.200"
                >
                  Preview will appear here
                </Box>
              )}
            </Box>
          </AspectRatioBox>
        </Flex>
        <Flex py="4" justifyContent="center">
          {blobReady && uploadSuccessful.uploadState !== "complete" && (
            <Button isDisabled={!blobReady} ml="4" onClick={uploadVideo}>
              {uploading ? <Spinner /> : "Upload Video"}
            </Button>
          )}
          {!!uploadSuccessful.videoUrl.length && (
           <CopyLink value={uploadSuccessful.videoUrl} />
          )}
        </Flex>
      </Container>
    </Layout>
  );
}
