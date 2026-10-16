import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  base: "/ui/",
  plugins: [react(), tailwindcss()],
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
