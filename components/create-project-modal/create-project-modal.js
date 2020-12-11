import React, { useState } from "react";
import {
  Modal,
  ModalOverlay,
  ModalContent,
  ModalCloseButton,
  Container,
  Stack,
  Heading,
  Input,
  FormControl,
  FormLabel,
  Button,
} from "@chakra-ui/react";
import { mutate } from "swr";
import fetcher from "utils/fetcher";
import SwatchList from "components/swatch-list/swatch-list";
import colors from "components/swatch-list/project-colors";

const CreateProjectModal = ({ isOpen, onClose }) => {
  const [selectedSwatch, setSelectedSwatch] = useState(colors[0].label);
  const [loading, setLoading] = useState(false);
  const [value, setValue] = useState("");

  const createNewProject = () => {
    mutate("/api/project/list", async ({ projects }) => {
      try {
        setLoading(true);
        const project = await fetcher("/api/project/create", {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            projectDetails: { name: value, color: selectedSwatch },
          }),
        });

        onClose();
        return { projects: [...projects, project.userProject] };
      } catch (error) {
        console.error(error);
      } finally {
        setLoading(false);
      }
    });
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose}>
      <ModalOverlay />
      <ModalContent maxW="100vw" h="100vh" m="0" rounded="none">
        <ModalCloseButton />
        <Container>
          <Stack h="100vh" align="center" justify="center">
            <Heading size="lg" fontWeight="medium" mb="8">
              Create a new project
            </Heading>
            <FormControl>
              <FormLabel>Project Name</FormLabel>
              <Input
                placeholder="2020 Ad Campaign"
                value={value}
                onChange={(event) => setValue(event.target.value)}
              />
            </FormControl>
            <FormControl py="4">
              <FormLabel>Thumbnail Color: {selectedSwatch} </FormLabel>
              <SwatchList
                selectedSwatch={selectedSwatch}
                setSelectedSwatch={setSelectedSwatch}
              />
            </FormControl>
            <Button
              isLoading={loading}
              colorScheme="teal"
              onClick={createNewProject}
            >
              Create Project
            </Button>
          </Stack>
        </Container>
      </ModalContent>
    </Modal>
  );
};

export default CreateProjectModal;
