/* eslint-disable jsx-a11y/media-has-caption */
import React from "react";
import {
  AspectRatio,
  Avatar,
  AvatarGroup,
  Box,
  Center,
  Container,
  Heading,
  SimpleGrid,
  Stack,
  Stat,
  StatLabel,
  StatNumber,
  Text,
  useDisclosure,
} from "@chakra-ui/react";
import useSWR from "swr";
import Link from "next/link";
import Layout from "components/layout/layout";
import CreateButton from "components/create-button/create-button";
import fetcher from "utils/fetcher";
import CreateProjectModal from "../components/create-project-modal/create-project-modal";

const Home = () => {
  const { isOpen, onOpen, onClose } = useDisclosure();
  const { data, error } = useSWR(`/api/project/list`, fetcher);

  return (
    <Layout>
      <Container maxW="100%" mt="4" p="8">
        <Box mb="8">
          <Heading size="md">Projects</Heading>
        </Box>
        <SimpleGrid columns={[1, 2, 3, 4, 6]} spacing="10">
          <CreateProjectModal onClose={onClose} isOpen={isOpen} />
          <CreateButton onClick={onOpen} />
          {data?.projects.map((details) => (
            <Link href={`/project/${details.project.id}`}>
              <Stack
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
                  rounded: "xl",
                }}
                _hover={{
                  _before: {
                    bg: "gray.100",
                  },
                  transform: "translateY(-5px)",
                }}
                transition="all 0.35s cubic-bezier(.08,.52,.52,1)"
                role="group"
              >
                <AspectRatio maxW="100%" ratio={1 / 1}>
                  <Box
                    p="4"
                    border="1px solid"
                    borderColor="gray.200"
                    rounded="xl"
                    boxShadow="0 2px 7px 0 rgba(0,0,0,0.1)"
                    bg="white"
                  >
                    <Stack h="100%" w="100%" justify="start" justifyContent="space-between">
                      <AvatarGroup size="sm" max={3}>
                        {details.project.user_projects.map((projectUser) => (
                          <Avatar name={projectUser.user.name} />
                        ))}
                      </AvatarGroup>
                      <Box mt="auto">
                        <Stack>
                          <Text fontSize="sm" color="gray.400" fontWeight="bold">
                            Last Updated
                          </Text>
                          <Text fontSize="sm" fontWeight="bold" mt="0">
                            {new Date(
                              details.project.updated_at
                            ).toLocaleDateString()}
                          </Text>
                        </Stack>
                      </Box>
                    </Stack>
                  </Box>
                </AspectRatio>
                <Text fontWeight="bold" position="relative" zIndex="2">
                  <Center>{details.project.project_name}</Center>
                </Text>
              </Stack>
            </Link>
          ))}
        </SimpleGrid>
      </Container>
    </Layout>
  );
};

export default Home;
