import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    watch: {
      // Browser-test traces and generated experiment artifacts must not cause
      // recursive full-page reloads while the live demo is running.
      ignored: [
        "**/.playwright-cli/**",
        "**/output/playwright/**",
        "**/.pytest-*/**",
        "**/artifacts/**",
      ],
    },
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
});
