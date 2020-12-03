import { Stack } from "@chakra-ui/react";
import React from "react";
import ColorSwatch from "../color-swatch/color-swatch";
import colors from "./project-colors";

const SwatchList = ({ selectedSwatch, setSelectedSwatch }) => {
  return (
    <Stack spacing={5} direction="row">
      {colors.map((swatch) => (
        <ColorSwatch
          color={swatch.color}
          label={swatch.label}
          onClick={() => setSelectedSwatch(swatch.label)}
          selected={selectedSwatch === swatch.label}
        />
      ))}
    </Stack>
  );
};

export default SwatchList;
