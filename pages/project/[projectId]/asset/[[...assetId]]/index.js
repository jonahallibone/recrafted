import React, { useState } from "react";
import {
  Avatar,
  Box,
  Button,
  Container,
  Flex,
  Grid,
  GridItem,
  Heading,
  IconButton,
  Image,
  Menu,
  MenuButton,
  MenuItem,
  MenuList,
  SimpleGrid,
  Skeleton,
  Stack,
  Text,
  Textarea,
  useDisclosure,
} from "@chakra-ui/react";
import { useRouter } from "next/router";
import Link from "next/link";
import useSWR from "swr";
import fetcher from "utils/fetcher";
import { Layers, MoreHorizontal } from "react-feather";
import Layout from "components/layout/layout";
import { ChevronDownIcon, ChevronLeftIcon } from "@chakra-ui/icons";
import { useAuthProvider } from "contexts/auth-provider";
import CreateRevisionModal from "components/create-revision-modal/create-revision-modal";

const Asset = () => {
  const router = useRouter();
  const { assetId, projectId } = router.query;

  const [id, version, versionId] = assetId;

  const [currentAssetVersion, setCurrentAssetVersion] = useState(
    version && versionId ? versionId - 1 : 0
  );

  const { data, error } = useSWR(
    `/api/project/${projectId}/asset/${id}`,
    fetcher
  );

  const { auth } = useAuthProvider();
  const { isOpen, onOpen, onClose } = useDisclosure();

  return (
    <Layout nopadding>
      {data && (
        <CreateRevisionModal
          assetName={data.asset.name}
          isOpen={isOpen}
          onClose={onClose}
          assetId={id}
          projectId={projectId}
        />
      )}
      <Box
        borderBottom="1px solid"
        borderColor="gray.200"
        py="3"
        width="100%"
        zIndex="9"
        bg="white"
        top="57px"
      >
        <Container maxW="100%">
          <SimpleGrid columns="2" justify="center">
            <Box as={Flex} alignItems="center">
              <Link href={`/project/${projectId}`}>
                <a>
                  <IconButton
                    icon={
                      <ChevronLeftIcon
                        h="1.5rem"
                        w="1.5rem"
                        color="purple.500"
                      />
                    }
                  />
                </a>
              </Link>
              <Heading size="md" fontWeight="bold" ml="4">
                {data ? (
                  data.asset.name
                ) : (
                  <Skeleton height="35px" width="250px" />
                )}
              </Heading>
            </Box>
            <Stack direction="row" as={Flex} justifyContent="flex-end">
              <Button
                leftIcon={<Layers size="18px" />}
                colorScheme="blue"
                variant="solid"
                onClick={onOpen}
              >
                New Revision
              </Button>
              <Menu>
                <MenuButton ml="4" as={Button} rightIcon={<ChevronDownIcon />}>
                  {data ? (
                    `v${currentAssetVersion + 1}`
                  ) : (
                    <Skeleton h="20px" w="20px" />
                  )}
                </MenuButton>
                <MenuList>
                  {data &&
                    data.asset.revisions.map((_, index) => (
                      <MenuItem onClick={() => setCurrentAssetVersion(index)}>
                        v{`${index + 1}`}.0
                      </MenuItem>
                    ))}
                </MenuList>
                <IconButton icon={<MoreHorizontal />} />
              </Menu>
            </Stack>
          </SimpleGrid>
        </Container>
      </Box>
      <Box>
        <Container maxW="100%" p="0">
          <Grid
            templateColumns="repeat(5, 1fr)"
            height="calc(100vh - 138px)"
            overflow="hidden"
          >
            <GridItem
              colSpan={4}
              maxHeight="100%"
              overflowY="auto"
              maxH="calc(100vh - 138px)"
            >
              <Stack>
                {data ? (
                  <Image
                    src={`https://d2iutcxiokgxnt.cloudfront.net/${data.asset.revisions[currentAssetVersion].files[0].src}`}
                    objectFit="contain"
                  />
                ) : (
                  <Skeleton h="100%" w="100%" />
                )}
              </Stack>
            </GridItem>
            <GridItem
              colSpan={1}
              minW="350px"
              borderLeft="1px solid"
              borderRight="1px solid"
              borderColor="gray.200"
              h="100%"
            >
              <Stack>
                <Box
                  borderBottom="1px solid"
                  borderColor="gray.200"
                  px="4"
                  pt="4"
                >
                  <Heading size="xs">Description</Heading>
                  <Text mt="2">
                    Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut
                    at eros nec sapien tincidunt pulvinar. Sed viverra augue
                    metus, vel sagittis nulla vulputate a. Aenean mauris enim,
                    facilisis vitae urna in, suscipit luctus lacus.
                  </Text>
                  <Stack direction="row">
                    <Box mt="4">
                      <Heading
                        p="2"
                        size="xs"
                        borderBottom="2px solid"
                        borderColor="purple.500"
                      >
                        Comments
                      </Heading>
                    </Box>
                  </Stack>
                </Box>
                <Box p="4">
                  <Box
                    rounded="md"
                    border="1px solid"
                    borderColor="gray.200"
                    p="2"
                  >
                    <Stack>
                      <Stack direction="row">
                        <Avatar
                          size="xs"
                          name={auth.user.name}
                          src={auth.user.picture}
                        />
                        <Textarea
                          border="none"
                          placeholder="Type your comment here..."
                          _focus={{
                            outline: "none",
                          }}
                        />
                      </Stack>
                      <Stack
                        direction="row"
                        justify="flex-end"
                        borderTop="1px solid"
                        borderColor="gray.200"
                        pt="2"
                      >
                        <Button size="sm" colorScheme="blue">
                          Send
                        </Button>
                      </Stack>
                    </Stack>
                  </Box>
                </Box>
              </Stack>
            </GridItem>
          </Grid>
        </Container>
      </Box>
    </Layout>
  );
};

export default Asset;
