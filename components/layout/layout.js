import { Box } from "@chakra-ui/react";
import React from "react";
import Head from "next/head";

const Layout = ({ nopadding = false, noMinH = false, children }) => (
  <Box
    minHeight={noMinH ? "calc(100vh - 57px)" : 0}
    mt="56px"
    pt={nopadding ? 0 : 4}
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
