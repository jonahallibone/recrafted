import React from "react";
import { Box } from "@chakra-ui/core";

const Container = ({ children, padded, ...rest }) => {
  return (
    <Box maxWidth="1440px" m="0 auto" width="100%" px={padded ? 4 : 0} {...rest}>
      {children}
    </Box>
  );
};

export default Container;
