import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: "/ui/",
  plugins: [react()],
  build: {
    outDir: "../dist",
    // Keep the tracked embed placeholder. Release/CI builds start from a clean
    // checkout; local rebuilds may retain older hashed assets.
    emptyOutDir: false,
    sourcemap: false,
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8081",
    },
  },
});
