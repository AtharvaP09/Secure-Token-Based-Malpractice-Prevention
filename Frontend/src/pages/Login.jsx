import { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate, Link } from 'react-router-dom';
import { Lock, User, LayoutDashboard } from 'lucide-react';

const Login = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const { login } = useAuth();
    const navigate = useNavigate();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        try {
            await login(username, password);
            // Determine redirection based on role - but login only returns true/false or user obj?
            // actually login updates 'user' state asynchronously. 
            // We can get decoded token from AuthContext if we waiting or simply decode again/check access_token return
            // The login function in AuthContext returns true on success.
            // But we need to know the role to redirect.
            // Let's rely on the updated state or decode manually here for speed.
            // Or better, let AuthContext return the user object or role.
            // Checking AuthContext.jsx: `setUser({ ...decoded, token: access_token });`
            // It returns `true`.
            // We can decode locally or modify AuthContext to return the user info.
            // Let's modify logic slightly:
            const token = sessionStorage.getItem('token');
            // Simple parse for now (we could use jwt-decode but already imported in context)
            // Actually, we can just fetch user from context? No, state update might not be immediate in this render cycle.
            // Let's reload or just use a helper. 
            // Actually simple redirection to a protected route wrapper is better, but for now:
            // We will blindly redirect to /dashboard and let a wrapper handle it? 
            // No, we have separate /teacher and /student routes.
            // Let's trust that we can get the role.

            // Creating a temporary decode to be safe:
            const payload = JSON.parse(atob(token.split('.')[1]));
            if (payload.role === 'admin') {
                navigate('/admin');
            } else if (payload.role === 'teacher') {
                navigate('/teacher');
            } else {
                navigate('/student');
            }

        } catch (err) {
            setError('Invalid credentials');
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-900 bg-opacity-95 bg-[url('https://images.unsplash.com/photo-1451187580459-43490279c0fa?q=80&w=2072&auto=format&fit=crop')] bg-cover bg-center bg-no-repeat bg-blend-overlay">
            <div className="bg-gray-800 bg-opacity-50 backdrop-blur-xl p-8 rounded-2xl shadow-2xl w-full max-w-md border border-gray-700">
                <div className="text-center mb-8">
                    <div className="mx-auto w-12 h-12 bg-blue-600 rounded-full flex items-center justify-center mb-4 shadow-lg shadow-blue-500/30">
                        <Lock className="text-white w-6 h-6" />
                    </div>
                    <h2 className="text-3xl font-bold text-white tracking-tight">Welcome Back</h2>
                    <p className="text-gray-400 mt-2">Sign in to the Secure Exam System</p>
                </div>

                {error && (
                    <div className="bg-red-500/10 border border-red-500/50 text-red-200 px-4 py-3 rounded-lg mb-6 text-sm">
                        {error}
                    </div>
                )}

                <form onSubmit={handleSubmit} className="space-y-6">
                    <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">Username</label>
                        <div className="relative">
                            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <User className="h-5 w-5 text-gray-500" />
                            </div>
                            <input
                                type="text"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                className="block w-full pl-10 pr-3 py-2.5 bg-gray-900/50 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                                placeholder="Enter your username"
                                required
                            />
                        </div>
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">Password</label>
                        <div className="relative">
                            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <Lock className="h-5 w-5 text-gray-500" />
                            </div>
                            <input
                                type="password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                className="block w-full pl-10 pr-3 py-2.5 bg-gray-900/50 border border-gray-600 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
                                placeholder="••••••••"
                                required
                            />
                        </div>
                    </div>

                    <button
                        type="submit"
                        className="w-full flex justify-center py-3 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors shadow-lg shadow-blue-600/30"
                    >
                        Sign In
                    </button>
                </form>

                <div className="mt-6 text-center">
                    <p className="text-sm text-gray-400">
                        Don't have an account?{' '}
                        <Link to="/register" className="font-medium text-blue-400 hover:text-blue-300 transition-colors">
                            Sign up
                        </Link>
                    </p>
                </div>
            </div>
        </div>
    );
};

export default Login;
