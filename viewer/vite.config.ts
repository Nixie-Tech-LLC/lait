import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

/**
 * The client builds straight into `src/serve/assets`, which is **committed**.
 *
 * That looks wrong until you line up three facts: `Cargo.toml` excludes `viewer/`
 * from the published crate, `publish-crates.yml` is Rust-only, and `build.rs`
 * deliberately never shells out to git so that `cargo install lait` stays
 * reproducible with no external toolchain. So the bundle cannot be built during
 * `cargo build` (that would need npm) and cannot live in `viewer/` (that never
 * reaches crates.io). Committing the built output under `src/` is what keeps
 * `lait serve` a single self-contained binary for people who install from source.
 *
 * The tradeoff is honest: build output in git, kept fresh by `npm run build` and
 * guarded by CI diffing a rebuild.
 */
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "../src/serve/assets",
    emptyOutDir: true,
    // No hashed filenames: the bundle is committed, so stable names keep the diff
    // legible and stop every rebuild from churning the tree with new files. The
    // binary is versioned as a whole, so we gain nothing from cache-busting names.
    rollupOptions: {
      output: {
        entryFileNames: "app.js",
        chunkFileNames: "[name].js",
        assetFileNames: "[name][extname]",
      },
    },
  },
  server: {
    port: 5178,
    proxy: {
      // Dev runs the client on :5178 and the engine on :7717 — two origins. That
      // is exactly what `serve::auth` refuses, and rightly: relaxing the guard for
      // developer convenience is how the guard stops meaning anything. So the
      // *proxy* adapts instead, and production stays same-origin with no dev flag
      // in the binary at all.
      "/api": {
        target: "http://127.0.0.1:7717",
        // Rewrites Host to the target, so the loopback-authority check passes.
        changeOrigin: true,
        configure: (proxy) => {
          proxy.on("proxyReq", (proxyReq) => {
            // Drop the browser's `Origin: http://localhost:5178`. Absent Origin is
            // allowed by design (curl, same-origin GETs) — and a proxied request
            // cannot be a page tricked into carrying our cookie, which is the only
            // thing that pair defends against.
            proxyReq.removeHeader("origin");
            // The cookie belongs to :5178's jar, which the engine never set. Carry
            // the run's token explicitly instead: `LAIT_TOKEN=... npm run dev`,
            // read from the URL `lait serve` prints.
            const token = process.env.LAIT_TOKEN;
            if (token) proxyReq.setHeader("authorization", `Bearer ${token}`);
          });
        },
      },
    },
  },
});
