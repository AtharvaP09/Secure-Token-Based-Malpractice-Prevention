import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/static': 'http://localhost:8000',
      '/exams': 'http://localhost:8000',
      '/auth': 'http://localhost:8000',
      '/users': 'http://localhost:8000',
    }
  }
})
