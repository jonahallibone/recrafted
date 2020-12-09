/* eslint-disable jsx-a11y/media-has-caption */
import React from "react";
import {
  AspectRatio,
  Box,
  Center,
  Container,
  Heading,
  SimpleGrid,
  Stack,
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
      <Container maxW="100%" mt="4">
        <Box mb="8">
          <Heading size="md">Projects</Heading>
        </Box>
        <SimpleGrid columns={[1, 2, 3, 4, 6]} spacing="10">
          <CreateProjectModal
            onClose={onClose}
            isOpen={isOpen}
          />
          <CreateButton onClick={onOpen} />
          {data?.projects.map((project) => (
            <Link href={`/project/${project.project.id}`}>
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
                    bg={project.project.thumbnail_color ?? "green.500"}
                    _groupHover={{ borderColor: "white" }}
                    rounded="xl"
                    boxShadow="0 3px 0 0 #48BB78"
                  />
                </AspectRatio>
                <Text fontWeight="bold" position="relative" zIndex="2">
                  <Center>{project.project.project_name}</Center>
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
