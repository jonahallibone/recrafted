import React from "react";
import useWindowSize from "hooks/use-window-size";
import Confetti from "react-confetti";

const BrowserConfetti = ({handleEnd}) => {
  const { width, height } = useWindowSize();

  if (typeof window !== "undefined") {
    return <Confetti width={width} height={height} recycle={false} onConfettiComplete={handleEnd} />;
  }

  return null;
};

export default BrowserConfetti;
