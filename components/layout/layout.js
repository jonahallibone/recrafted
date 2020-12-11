import { Box, Grid, GridItem } from "@chakra-ui/react";
import React from "react";
import Head from "next/head";

const Layout = ({ nopadding = false, noMinH = false, children }) => (
  <Box
    boxSizing={nopadding ? "content-box" : "border-box"}
  >
    <Head>
      <title>Recrafted | Feedback for teams</title>
      <meta name="viewport" content="initial-scale=1.0, width=device-width" />
    </Head>
    {children}
  </Box>
);

export default Layout;
