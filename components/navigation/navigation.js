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
        bg="blue.700"
        transition="all 0.2s"
        rounded="md"
        _hover={{ bg: "blue.500" }}
        _expanded={{ bg: "blue.600" }}
        _focus={{ outline: 0, boxShadow: "outline" }}
        _active={{ bg: "blue.400" }}
      >
        <MemoizedAvatar />
        <Flex>
          <Text display={["none", "none", "block"]}>{auth.user.name}</Text> <Icon name="chevron-down" ml="2" />
        </Flex>
      </MenuButton>
      <MenuList bg="blue.600">
        <MenuItem
          _focus={{ bg: "blue.500" }}
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
      variantColor="cyan"
      onClick={login}
      mx={2}
    >
      Login
    </Button>
  );

  const SignUpButton = () => (
    <Button
      variantColor="green"
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
      bg="white"
      borderBottom="1px solid"
      borderBottomColor="gray.200"
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
                fontSize="2xl"
                fontWeight="bold"
                color="black"
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
