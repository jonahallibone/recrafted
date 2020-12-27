import React from "react";
import { Avatar, Box, Flex, Icon, IconButton, Skeleton, Stack, StackItem } from "@chakra-ui/react";
import { formatDistance, formatRelative, subDays } from "date-fns";
import { MoreHorizontal } from "react-feather";

const Comment = ({ comment }) => (
  <Box p="2" border="1px solid" borderColor="gray.200" rounded="md">
    <Box>
      <Stack direction="row" align="center" justify="space-between">
        <Stack flexDirection="row" align="center" spacing="0">
          <Avatar size="sm" name={comment.author.name} mr="2" />
          <Stack spacing="0">
            <Box fontWeight="500">{comment.author.name}</Box>
            <Box textTransform="capitalize" fontSize="xs">
              {formatDistance(new Date(comment.created_at), new Date())} ago
            </Box>
          </Stack>
        </Stack>
        <Stack>
          <IconButton icon={<MoreHorizontal />} size="xs" variant="link" />
        </Stack>
      </Stack>
      <Stack>
        <Box my="2">{comment.description}</Box>
      </Stack>
    </Box>
  </Box>
);

export default Comment;
