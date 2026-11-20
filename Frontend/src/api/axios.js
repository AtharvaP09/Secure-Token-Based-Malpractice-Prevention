
import axios from 'axios';

// Backend API URL
const API_BASE_URL =
    import.meta.env.VITE_API_URL ||
    'https://secure-token-based-malpractice-prevention.onrender.com';

const api = axios.create({
    baseURL: API_BASE_URL,
});

// Attach JWT token to every request automatically
api.interceptors.request.use(
    (config) => {
        const token = sessionStorage.getItem('token');

        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }

        return config;
    },
    (error) => Promise.reject(error)
);

export default api;
