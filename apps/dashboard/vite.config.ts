import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dev server proxies /api to the backend so the browser talks to one origin.
const apiTarget = process.env.AEGIS_API_URL ?? "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, strictPort: true, proxy: { "/api": apiTarget } },
  preview: { port: 4173, proxy: { "/api": apiTarget } },
});
