import { Box } from "@chakra-ui/core";
import React from "react";
import Head from "next/head";

const Layout = ({ nopadding = false, children }) => (
  <Box
    minHeight="calc(100vh - 57px)"
    mt="56px"
    pt={nopadding ? 0 : 4}
    px={nopadding ? 0 : 4}
    boxSizing={nopadding ? "content-box" : "border-box"}
  >
    <Head>
      <title>Tab Grab | Share a Screen Recording</title>
      <meta name="viewport" content="initial-scale=1.0, width=device-width" />
    </Head>
    {children}
  </Box>
);

export default Layout;
