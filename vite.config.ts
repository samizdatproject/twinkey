import { defineConfig } from 'vite';
// base './' so the build works under GitHub Pages' /twinkey/ path; two pages: the identity tool and the demo app.
export default defineConfig({
  base: './',
  build: { target: 'es2022', rollupOptions: { input: { main: 'index.html', app: 'app.html' } } },
});
