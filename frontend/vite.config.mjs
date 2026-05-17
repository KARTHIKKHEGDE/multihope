import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const configText = readFileSync(resolve(import.meta.dirname, "..", "backend", "config.py"), "utf-8");
const host = configText.match(/HOST = "([^"]+)"/)?.[1];
const apiPort = configText.match(/API_PORT = (\d+)/)?.[1];

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": `http://${host}:${apiPort}`,
    },
  },
});
