import { defineConfig } from 'vite';
// base './' so the build works under GitHub Pages' /twinkey/ path; two pages: the identity tool and the demo app.
// es2022 everywhere: libauth initialises its WASM crypto with a top-level await.
export default defineConfig({
  base: './',
  build: { target: 'es2022', rollupOptions: { input: { main: 'index.html', app: 'app.html' } } },
  optimizeDeps: { esbuildOptions: { target: 'es2022' } },
});
