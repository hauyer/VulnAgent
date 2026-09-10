import express from "express";
import cors from "cors";
import path from "path";
import { createServer as createViteServer } from "vite";
import { apiRouter } from "./server/routes.js";

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(cors());
  app.use(express.json());

  // Mount API endpoints with and without /api prefix for full compatibility
  app.use("/api", apiRouter);
  app.use(apiRouter);

  // Vite middleware for development / static serving for production
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`VulnAgent server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
