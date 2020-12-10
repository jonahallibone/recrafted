import { PrismaClient } from "@prisma/client";
import fs from "fs";
import { spawnSync } from "child_process";

if (process.env.NODE_ENV === "production") {
  const binaryPath = "/tmp/query-engine-rhel-openssl-1.0.x";

  if (!fs.existsSync(binaryPath)) {
    spawnSync("cp", [
      `${process.env.LAMBDA_TASK_ROOT}/node_modules/.prisma/client/query-engine-rhel-openssl-1.0.x`,
      "/tmp/",
    ]);

    spawnSync("chmod", [`555`, "/tmp/query-engine-rhel-openssl-1.0.x"]);
  }
}

const Prisma = new PrismaClient();
export default Prisma;
