import React from "react";
import Link from "next/link";
import { Box } from "@chakra-ui/react";
import { useRouter } from "next/router";

const SidebarLink = ({ children, href }) => {
  const router = useRouter();
  const { pathname } = router;
  const isActive = pathname === href;
  return (
    <Link href={href}>
      <Box
        as="a"
        fontWeight="bold"
        bg={isActive ? "gray.800" : "transparent"}
        color="white"
        px="4"
        py="3"
        borderLeft="2px solid"
        borderColor={isActive ? "gray.500" : "transparent"}
        cursor="pointer"
        display="flex"
        alignItems="center"
      >
        {children}
      </Box>
    </Link>
  );
};

export default SidebarLink;
