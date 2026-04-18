require("dotenv").config();
const app = require("./app");
const { initFirebase } = require("./config/firebase");

const PORT = process.env.PORT || 3001;

(async () => {
  try {
    initFirebase();
    app.listen(PORT, () => {
      console.log(`[Server] Tower Dump Analysis backend running on port ${PORT}`);
      console.log(`[Server] Environment: ${process.env.NODE_ENV || "development"}`);
    });
  } catch (err) {
    console.error("[Server] Failed to start:", err.message);
    process.exit(1);
  }
})();
