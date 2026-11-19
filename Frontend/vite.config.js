import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  // Proxy is only used in local development (npm run dev).
  // In production on Vercel, VITE_API_URL env var points to the Render backend.
  server: {
    proxy: {
      '/static': 'http://localhost:8000',
      '/exams':  'http://localhost:8000',
      '/auth':   'http://localhost:8000',
      '/users':  'http://localhost:8000',
    }
  }
})
