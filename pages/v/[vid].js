import React from "react";
import Layout from "components/layout/layout";
import Container from "components/container/container";
import fetcher from "utils/fetcher";

const Recording = ({ recording, error = null }) => {
  return (
    <Layout>
      <Container>
        {!error ? (
          <video
            src={`https://d2iutcxiokgxnt.cloudfront.net/${recording.s3_ref}`}
            autoPlay
            playsInline
            controls
          />
        ) : (
          JSON.stringify(error)
        )}
      </Container>
    </Layout>
  );
};

export const getServerSideProps = async ({ params, req }) => {
  try {
    const recording = await fetcher(
      `${process.env.BASE_URL}/api/recording/${params.vid}`
    );
    console.log(`${process.env.BASE_URL}/api/recording/${params.vid}`);
    return {
      props: recording,
    };
  } catch (error) {
    return {
      props: error,
    };
  }
};

export default Recording;
