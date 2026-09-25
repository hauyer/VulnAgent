import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { resolve } from "node:path";

// Build output lands in the repository-root dist/ so the FastAPI factory can
// serve the production UI from repository_root/dist.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: resolve(__dirname, "../dist"),
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8000",
    },
  },
});
