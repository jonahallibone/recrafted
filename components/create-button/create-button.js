import { AddIcon } from "@chakra-ui/icons";
import { AspectRatio, Box, Center, Stack, Text } from "@chakra-ui/react";
import React from "react";

const CreateButton = ({ onClick }) => {
  return (
    <Stack
      onClick={onClick}
      direction="column"
      rounded="xl"
      cursor="pointer"
      color="gray.700"
      position="relative"
      _before={{
        content: '""',
        height: "calc(100% + 2em)",
        width: "calc(100% + 2em)",
        position: "absolute",
        top: "50%",
        left: "50%",
        transition: "all 0.2s cubic-bezier(.08,.52,.52,1)",
        transform: "translate(-50%, -50%)",
        rounded: "xl"
      }}
      _hover={{
        _before: {
          bg: "gray.100",
        },
        transform: "translateY(-5px)"
      }}
      transition="all 0.35s cubic-bezier(.08,.52,.52,1)"
      role="group"
    >
      <AspectRatio maxW="100%" ratio={1 / 1}>
        <Box
          border="2px dashed"
          borderColor="gray.400"
          rounded="xl"
          bg="white"
        >
          <AddIcon color="currentColor" w={4} h={4} />
        </Box>
      </AspectRatio>
      <Text fontWeight="bold" position="relative" zIndex="2">
        <Center>Add Project</Center>
      </Text>
    </Stack>
  );
};

export default CreateButton;
