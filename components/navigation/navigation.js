import React, { useCallback } from "react";
import {
  Avatar,
  Box,
  Container,
  Flex,
  Menu,
  MenuButton,
  MenuList,
  MenuItem,
  Button,
  Text,
  Grid,
  GridItem,
  Stack,
  Icon,
  Badge,
} from "@chakra-ui/react";
import Link from "next/link";
import { LogOut, Grid as GridIcon, Bell, File } from "react-feather";
import { ChevronDownIcon } from "@chakra-ui/icons";
import { useAuthProvider } from "contexts/auth-provider";
import SidebarLink from "components/sidebar-link/sidebar-link";

const Navigation = ({ children }) => {
  const { auth, logout, login } = useAuthProvider();

  const MemoizedAvatar = useCallback(
    () => (
      <Avatar size="xs" mr="2" name={auth.user.name} src={auth.user.picture} />
    ),
    [auth]
  );

  const UserMenu = () => (
    <Menu>
      <MenuButton
        as={Button}
        bg="gray.200"
        transition="all 0.2s"
        rounded="md"
        _hover={{ bg: "gray.300" }}
        _expanded={{ bg: "gray.400" }}
        _focus={{ outline: 0, boxShadow: "outline" }}
        _active={{ bg: "gray.400" }}
        rightIcon={<ChevronDownIcon />}
        color="gray.800"
      >
        <Flex align="center">
          <MemoizedAvatar />
          {auth.user.name}
        </Flex>
      </MenuButton>
      <MenuList bg="gray.200">
        <MenuItem
          _focus={{ bg: "gray.300" }}
          fontWeight="medium"
          onClick={logout}
          color="gray.700"
        >
          <Box
            as={LogOut}
            color="gray.700"
            size="16px"
            mr="2"
            strokeWidth={2.5}
          />{" "}
          Logout
        </MenuItem>
      </MenuList>
    </Menu>
  );

  const LoginButton = () => (
    <Button colorScheme="cyan" onClick={login} mx={2}>
      Login
    </Button>
  );

  const SignUpButton = () => (
    <Button colorScheme="green" onClick={login} mx="2">
      Sign Up
    </Button>
  );

  const LoginOrSignUp = () => (
    <Flex>
      <LoginButton />
      <SignUpButton />
    </Flex>
  );

  return (
    <Container maxWidth="100%" px="0">
      <Grid templateColumns="250px 1fr" h="100vh">
        <GridItem bg="black">
          <Stack>
            <Box
              d="flex"
              justifyContent="space-between"
              w="100%"
              color="white"
              py={4}
              top="0"
              left="0"
              zIndex="99"
              px="4"
            >
              <Link href="/">
                <Box
                  flex="0 0 50%"
                  d="flex"
                  alignItems="center"
                  cursor="pointer"
                >
                  <Text fontSize="2xl" fontWeight="bold" color="white">
                    recraft
                  </Text>
                </Box>
              </Link>
            </Box>
            <Box>
              <Stack direction="column">
                <SidebarLink href="/">
                  <Icon as={GridIcon} mr="4" /> Projects
                </SidebarLink>
                <SidebarLink href="/alerts">
                  <Icon as={Bell} mr="4" /> Alerts <Badge ml="4" colorScheme="red">0</Badge>
                </SidebarLink>
                <SidebarLink href="/assets">
                  <Icon as={File} mr="4" /> Assets
                </SidebarLink>
              </Stack>
            </Box>
          </Stack>
        </GridItem>
        <GridItem>
          <Box
            d="flex"
            justifyContent="space-between"
            bg="white"
            w="100%"
            color="white"
            py={4}
            top="0"
            left="0"
            zIndex="99"
          >
            <Container maxW="100%">
              <Flex justifyContent="flex-end">
                <Box flex="0 0 50%" d="flex" justifyContent="flex-end">
                  {auth.authenticated ? <UserMenu /> : <LoginOrSignUp />}
                </Box>
              </Flex>
            </Container>
          </Box>
          <Box maxH="calc(100vh - 72px)" overflowY="scroll">
            {children}
          </Box>
        </GridItem>
      </Grid>
    </Container>
  );
};

export default Navigation;
