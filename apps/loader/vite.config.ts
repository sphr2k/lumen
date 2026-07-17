import { defineConfig } from "vite";

export default defineConfig({
  root: "apps/loader",
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true
  }
});
