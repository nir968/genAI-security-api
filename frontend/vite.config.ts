import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// The browser only ever talks to "/api". In production nginx forwards it to the
// gateway; in dev (and `vite preview`) Vite does, so no CORS setup is needed.
const gatewayProxy = {
  '/api': {
    target: 'http://127.0.0.1:8000',
    changeOrigin: true,
    rewrite: (path: string) => path.replace(/^\/api/, ''),
  },
};

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { proxy: gatewayProxy },
  preview: { proxy: gatewayProxy },
});
