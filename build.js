const childProcess = require("child_process");

const env = {
  ...process.env,
  // Avoid embedding timestamps into linked binary on macOS
  ZERO_AR_DATE: "1",
};

childProcess.execSync("npx node-gyp-build", {
  env,
  stdio: "inherit",
});
