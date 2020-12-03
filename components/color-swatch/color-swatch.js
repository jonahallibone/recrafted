import { Box, Button, Flex, Tooltip } from "@chakra-ui/react";
import React from "react";
import { CheckIcon } from "@chakra-ui/icons";

const ColorSwatch = ({ color, onClick, label, selected }) => {
  return (
    <Tooltip label={label}>
      <Box
        as={Button}
        onClick={onClick}
        bg={color}
        h="40px"
        w="40px"
        borderRadius="50%"
        border="1px solid"
        borderColor="gray.200"
        position="relative"
        _hover={{
          bg: color,
        }}
        overflow="hidden"
      >
        {selected && (
          <Box
            as={Flex}
            alignItems="center"
            justifyContent="center"
            position="absolute"
            h="100%"
            w="100%"
            background="rgba(255,255,255, 0.4)"
          >
            <CheckIcon />
          </Box>
        )}
      </Box>
    </Tooltip>
  );
};

export default ColorSwatch;
