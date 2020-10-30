/* eslint-disable jsx-a11y/media-has-caption */
import React, { useRef, useState } from "react";
import Head from "next/head";
import { Box, Button, Flex, SimpleGrid, Spinner } from "@chakra-ui/core";
import Layout from "components/layout/layout";
import Container from "components/container/container";

const MIME_TYPE = "video/webm";

export default function Home() {
  const videoPlayer = useRef(null);
  const finalBlob = useRef(null);
  const key = useRef(null);
  const [blobReady, setBlobReady] = useState();
  const [uploading, setUploading] = useState(false);
  const [uploadSuccessful, setUploadSuccessful] = useState(false);

  const getUploadURL = async () => {
    const req = await fetch("/api/aws/get-upload-url");
    return req.json();
  };

  const uploadVideo = async () => {
    const { uploadURL, shortID } = await getUploadURL();
    key.current = shortID;
    try {
      setUploading(true);
      fetch(uploadURL, {
        method: "PUT",
        body: finalBlob.current,
      });
    } catch (error) {
      console.error(error);
    } finally {
      setUploading(false);
      setUploadSuccessful(true);
    }
  };

  const handleStreamEnd = (streamBlob) => {
    videoPlayer.current.srcObject = null;
    videoPlayer.current.src = streamBlob;
    setBlobReady(true);
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
      captureStream = await navigator.mediaDevices.getDisplayMedia();
      videoPlayer.current.srcObject = captureStream;

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
      <Container>
        <Flex justifyContent="center">
          <Box>
            <video
              ref={videoPlayer}
              autoPlay
              playsInline
              controls
              muted
              style={{
                height: 600,
                background: "#FFF",
              }}
            />
          </Box>
        </Flex>
        <Flex py="4" justifyContent="center">
          <Button onClick={chooseTabToRecord}>Record New Video</Button>
          {blobReady && !uploadSuccessful && (
            <Button isDisabled={!blobReady} ml="4" onClick={uploadVideo}>
              {uploading ? <Spinner /> : "Upload Video"}
            </Button>
          )}
          {uploadSuccessful &&
            `${
              process.env.NODE_ENV === "development"
                ? `https://localhost:3000/${key.current}`
                : `https://tabgrab.app/${key.current}`
            }`}
        </Flex>
      </Container>
    </Layout>
  );
}
