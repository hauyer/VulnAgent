import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "");
  return {
    plugins: [react(), tailwindcss()],
    server: {
      host: "0.0.0.0",
      port: 5173,
      watch: {
        // Browser-test traces and generated experiment artifacts must not cause
        // recursive full-page reloads while the live demo is running.
        ignored: [
          "**/.playwright-cli/**",
          "**/.sites-runtime/**",
          "**/output/playwright/**",
          "**/.pytest-*/**",
          "**/artifacts/**",
          "**/output/**",
        ],
      },
      proxy: {
        "/api": {
          target: env.VITE_API_TARGET || "http://127.0.0.1:8000",
          changeOrigin: true,
        },
      },
    },
  };
});
