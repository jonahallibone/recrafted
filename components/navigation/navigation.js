import React, { useCallback } from "react";
import {
  Avatar,
  Box,
  Flex,
  Menu,
  MenuButton,
  MenuList,
  MenuItem,
  Icon,
  Button,
  Text,
  Image,
} from "@chakra-ui/core";
import Link from "next/link";
import { LogOut } from "react-feather";
import { useAuthProvider } from "../../contexts/auth-provider";
import Container from "../container/container";

const Navigation = () => {
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
        bg="teal.700"
        transition="all 0.2s"
        rounded="md"
        _hover={{ bg: "teal.500" }}
        _expanded={{ bg: "teal.600" }}
        _focus={{ outline: 0, boxShadow: "outline" }}
        _active={{ bg: "teal.400" }}
      >
        <MemoizedAvatar />
        <Flex>
          <Text display={["none", "none", "block"]}>{auth.user.name}</Text> <Icon name="chevron-down" ml="2" />
        </Flex>
      </MenuButton>
      <MenuList bg="teal.600">
        <MenuItem
          _focus={{ bg: "teal.500" }}
          fontWeight="medium"
          onClick={logout}
        >
          <Box as={LogOut} color="white" size="16px" mr="2" strokeWidth={2.5} />{" "}
          Logout
        </MenuItem>
      </MenuList>
    </Menu>
  );

  const LoginButton = () => (
    <Button
      bg="teal.300"
      _hover={{ bg: "teal.500" }}
      _expanded={{ bg: "teal.600" }}
      _focus={{ outline: 0, boxShadow: "outline" }}
      _active={{ bg: "teal.400" }}
      onClick={login}
      mx={2}
    >
      Login
    </Button>
  );

  const SignUpButton = () => (
    <Button
      bg="yellow.300"
      color="teal.400"
      _hover={{ bg: "yellow.200" }}
      _expanded={{ bg: "yellow.200" }}
      _focus={{ outline: 0, boxShadow: "outline" }}
      _active={{ bg: "yellow.200" }}
      onClick={login}
      mx="2"
    >
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
    <Box
      d="flex"
      justifyContent="space-between"
      bg="teal.400"
      w="100%"
      color="white"
      py={2}
      position="fixed"
      top="0"
      left="0"
      zIndex="999999"
    >
      <Container px={4}>
        <Flex>
          <Link href="/">
            <Box flex="0 0 50%" d="flex" alignItems="center" cursor="pointer">
              <Text
                display={["none", "none", "block"]}
                fontSize="2xl"
                fontWeight="bold"
                color="white"
              >
                TabGrab
              </Text>{" "}
            </Box>
          </Link>
          <Box flex="0 0 50%" d="flex" justifyContent="flex-end">
            {auth.authenticated ? <UserMenu /> : <LoginOrSignUp />}
          </Box>
        </Flex>
      </Container>
    </Box>
  );
};

export default Navigation;
