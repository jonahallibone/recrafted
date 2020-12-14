import React from "react";
import {
  Box,
  Button,
  Flex,
  Heading,
  Icon,
  Input,
  Stack,
  Text,
  useClipboard,
  useToast,
} from "@chakra-ui/react";

const CopyLink = ({ value }) => {
  const { onCopy } = useClipboard(value);
  const toast = useToast();

  const handleCopy = () => {
    onCopy();
    toast({
      duration: 3000,
      render: () => (
        <Box m={3} color="white" p={3} bg="blue.400" rounded="md">
          <Text fontWeight="bold">Link Copied!</Text>
          <Text>Paste this link anywhere</Text>
        </Box>
      ),
    });
  };

  return (
    <Stack mt="4" _first={{ mt: 0 }}>
      <Flex justifyContent="center">
        <Heading size="md">Share this recording</Heading>
      </Flex>
      <Box
        p="4"
        boxShadow="0 2px 7px 2px rgba(0,0,0,0.1)"
        border="1px solid"
        borderColor="gray.200"
        rounded="md"
      >
        <Stack isInline alignItems="center">
          <Input value={value} isReadOnly minW="320px" />
          <Button onClick={handleCopy}>
            <Icon name="copy" />
          </Button>
        </Stack>
      </Box>
    </Stack>
  );
};

export default CopyLink;
