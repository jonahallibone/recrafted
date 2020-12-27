import React, { useState } from "react";
import {
  Avatar,
  Box,
  Button,
  Skeleton,
  Stack,
  Textarea,
} from "@chakra-ui/react";
import { useRouter } from "next/router";
import { useAuthProvider } from "contexts/auth-provider";
import fetcher from "utils/fetcher";
import useSWR, { mutate } from "swr";
import Comment from "../comment/comment";

const CommentSidebar = ({ revisionId }) => {
  const router = useRouter();
  const { projectId, assetId } = router.query;

  const { auth } = useAuthProvider();
  const [commentValue, setCommentValue] = useState("");
  const [loading, setLoading] = useState(false);

  const { data, error } = useSWR(
    `/api/project/${projectId}/asset/${assetId}/revision/${revisionId}/comment`
  );

  console.log(data);

  const addComment = async (event) => {
    event.preventDefault();
    setLoading(true);
    const result = await fetcher(
      `/api/project/${projectId}/asset/${assetId}/revision/${revisionId}/comment/create`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          newComment: {
            description: commentValue,
            x: null,
            y: null,
          },
        }),
      }
    );
    
    setCommentValue("");

    mutate(
      `/api/project/${projectId}/asset/${assetId}/revision/${revisionId}/comment`,
      () =>  [...result.comments]
    );
    setLoading(false);
  };

  if (!data) {
    return (
      <Box rounded="md" border="1px solid" borderColor="gray.200" p="2">
        <Skeleton />
        <Skeleton />
        <Skeleton />
      </Box>
    );
  }

  return (
    <Box p="4">
      <Box rounded="md" border="1px solid" borderColor="gray.200" p="2">
        <Stack>
          <Stack direction="row">
            <Avatar size="xs" name={auth.user.name} src={auth.user.picture} />
            <Textarea
              value={commentValue}
              onChange={(e) => setCommentValue(e.target.value)}
              onKeyPress={(e) => e.key === "Enter" && !loading && addComment(e)}
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
            <Button
              size="sm"
              colorScheme="blue"
              onClick={addComment}
              isLoading={loading}
            >
              Send
            </Button>
          </Stack>
        </Stack>
      </Box>
      <Stack mt="2">
        {data.map((comment) => (
          <Comment comment={comment} />
        ))}
      </Stack>
    </Box>
  );
};

export default CommentSidebar;
