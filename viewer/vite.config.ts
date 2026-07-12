import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { laitApi } from "./server/api";

// The viewer is a plain Vite + React SPA. Its only backend is a dev-server
// middleware (`laitApi`) that shells out to the `lait --json` CLI, so both reads
// and writes flow through lait's real daemon -> Loro layer. One runtime, one
// port, no CORS, no second database.
export default defineConfig({
  plugins: [
    react(),
    {
      name: "lait-api",
      configureServer(server) {
        server.middlewares.use(laitApi());
      },
    },
  ],
  server: {
    port: 5178,
    strictPort: false,
  },
});
