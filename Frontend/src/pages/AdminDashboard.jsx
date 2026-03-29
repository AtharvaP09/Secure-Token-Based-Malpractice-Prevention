import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import api from '../api/axios';
import { Users, LogOut, Shield, Search, ArrowUpCircle, ArrowDownCircle } from 'lucide-react';

const AdminDashboard = () => {
    const { user, logout } = useAuth();
    const navigate = useNavigate();
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');

    const [createModalOpen, setCreateModalOpen] = useState(false);
    const [newUser, setNewUser] = useState({
        username: '',
        email: '',
        password: '',
        role: 'student'
    });

    useEffect(() => {
        if (user?.role !== 'admin') {
            navigate('/login');
            return;
        }
        fetchUsers();
    }, [user, navigate]);

    const fetchUsers = async () => {
        try {
            const response = await api.get('/auth/admin/users');
            setUsers(response.data);
        } catch (error) {
            console.error("Failed to fetch users", error);
        } finally {
            setLoading(false);
        }
    };

    const handleCreateUser = async (e) => {
        e.preventDefault();
        try {
            const response = await api.post('/auth/admin/users', newUser);
            setUsers([...users, response.data]);
            setCreateModalOpen(false);
            setNewUser({ username: '', email: '', password: '', role: 'student' });
            alert("User created successfully");
        } catch (error) {
            console.error("Failed to create user", error);
            alert(error.response?.data?.detail || "Failed to create user");
        }
    };

    const handleRoleUpdate = async (userId, newRole) => {
        try {
            await api.put(`/auth/admin/users/${userId}/role?role=${newRole}`);
            // Optimistic update
            setUsers(users.map(u => u.id === userId ? { ...u, role: newRole } : u));
        } catch (error) {
            console.error("Failed to update role", error);
            alert("Failed to update user role");
        }
    };

    const handleDeleteUser = async (userId) => {
        if (!window.confirm("Are you sure you want to delete this user? This action cannot be undone and will remove all their data.")) {
            return;
        }

        try {
            await api.delete(`/auth/admin/users/${userId}`);
            // Optimistic update
            setUsers(users.filter(u => u.id !== userId));
        } catch (error) {
            console.error("Failed to delete user", error);
            if (error.response && error.response.status === 401) {
                alert("Your session has expired. Please login again.");
                logout();
                navigate('/login');
            } else if (error.response && error.response.status === 400) {
                alert(error.response.data.detail || "Cannot delete this user.");
            } else {
                alert("Failed to delete user. Please try again.");
            }
        }
    };

    const handleLogout = () => {
        logout();
        navigate('/login');
    };

    const filteredUsers = users.filter(u =>
        u.username.toLowerCase().includes(searchTerm.toLowerCase()) ||
        u.email.toLowerCase().includes(searchTerm.toLowerCase())
    );

    return (
        <div className="min-h-screen bg-[#0A0F1C] bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-slate-900 via-[#0A0F1C] to-black text-white font-sans selection:bg-red-500/30">
            {/* Navbar */}
            <nav className="border-b border-indigo-900/30 bg-[#0A0F1C]/70 backdrop-blur-xl sticky top-0 z-50 shadow-lg">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between items-center h-16">
                        <div className="flex items-center space-x-3">
                            <div className="bg-gradient-to-br from-red-500 to-red-700 p-2.5 rounded-xl shadow-[0_0_15px_rgba(239,68,68,0.3)] border border-red-400/20">
                                <Shield className="h-6 w-6 text-white" />
                            </div>
                            <span className="text-xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-white to-gray-400">Admin Portal</span>
                        </div>
                        <div className="flex items-center space-x-4">
                            <div className="text-sm text-gray-400 hidden sm:block">
                                <span className="text-indigo-200/80 font-bold bg-indigo-500/10 px-3 py-1.5 rounded-lg border border-indigo-500/20">Administrator</span>
                            </div>
                            <button
                                onClick={handleLogout}
                                className="p-2 rounded-lg hover:bg-red-500/10 text-gray-400 hover:text-red-400 transition-all border border-transparent hover:border-red-500/20"
                                title="Logout"
                            >
                                <LogOut className="h-5 w-5" />
                            </button>
                        </div>
                    </div>
                </div>
            </nav>

            <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 relative z-10">
                <div className="mb-8 flex flex-col sm:flex-row justify-between items-center gap-4">
                    <div>
                        <h1 className="text-3xl font-bold text-white tracking-tight drop-shadow-lg text-transparent bg-clip-text bg-gradient-to-br from-white to-gray-400">User Management</h1>
                        <p className="text-indigo-200/60 mt-1 font-medium">Manage user roles and permissions</p>
                    </div>

                    <div className="flex items-center gap-4 w-full sm:w-auto">
                        <div className="relative w-full sm:w-64 group">
                            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                                <Search className="h-5 w-5 text-indigo-400/50 group-focus-within:text-blue-400 transition-colors" />
                            </div>
                            <input
                                type="text"
                                placeholder="Search users..."
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                                className="block w-full pl-10 pr-3 py-2.5 bg-[#0A0F1C]/80 border border-indigo-500/20 rounded-xl text-white placeholder-indigo-900/50 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent shadow-inner transition-all font-medium"
                            />
                        </div>
                        <button
                            onClick={() => setCreateModalOpen(true)}
                            className="px-5 py-2.5 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white rounded-xl font-bold transition-all shadow-[0_0_15px_rgba(239,68,68,0.3)] hover:scale-[1.02] active:scale-[0.98] flex items-center whitespace-nowrap"
                        >
                            <span className="mr-2 text-lg leading-none">+</span> Add User
                        </button>
                    </div>
                </div>

                {loading ? (
                    <div className="text-center py-12">
                        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-500 mx-auto drop-shadow-[0_0_10px_rgba(239,68,68,0.5)]"></div>
                        <p className="mt-4 text-indigo-200/60 font-medium">Loading users...</p>
                    </div>
                ) : (
                    <div className="bg-[#131B2F]/60 backdrop-blur-md rounded-2xl border border-indigo-500/10 overflow-hidden shadow-[0_8px_30px_rgb(0,0,0,0.12)]">
                        <div className="overflow-x-auto custom-scrollbar">
                            <table className="min-w-full divide-y divide-indigo-500/10">
                                <thead className="bg-[#0A0F1C]/50">
                                    <tr>
                                        <th className="px-6 py-4 text-left text-xs font-bold text-indigo-300 uppercase tracking-widest">User</th>
                                        <th className="px-6 py-4 text-left text-xs font-bold text-indigo-300 uppercase tracking-widest">Email</th>
                                        <th className="px-6 py-4 text-left text-xs font-bold text-indigo-300 uppercase tracking-widest">Role</th>
                                        <th className="px-6 py-4 text-right text-xs font-bold text-indigo-300 uppercase tracking-widest">Actions</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-indigo-500/10">
                                    {filteredUsers.map((u) => (
                                        <tr key={u.id} className="hover:bg-white/5 transition-colors group">
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <div className="flex items-center">
                                                    <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-indigo-500/20 to-blue-500/20 border border-indigo-500/30 flex items-center justify-center text-blue-300 font-bold shadow-inner">
                                                        {u.username.charAt(0).toUpperCase()}
                                                    </div>
                                                    <div className="ml-4">
                                                        <div className="text-sm font-bold text-gray-200 group-hover:text-blue-300 transition-colors">{u.username}</div>
                                                    </div>
                                                </div>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-indigo-300/70 font-medium">
                                                {u.email}
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <span className={`px-3 py-1 inline-flex text-[10px] font-bold tracking-wider uppercase rounded-full border shadow-sm ${u.role === 'admin' ? 'bg-red-500/10 text-red-400 border-red-500/30 shadow-[0_0_10px_rgba(239,68,68,0.1)]' :
                                                    u.role === 'teacher' ? 'bg-purple-500/10 text-purple-400 border-purple-500/30 shadow-[0_0_10px_rgba(168,85,247,0.1)]' :
                                                        'bg-[#131B2F]/60 text-indigo-300 border-indigo-500/20'
                                                    }`}>
                                                    {u.role}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                                {u.role !== 'admin' && (
                                                    <div className="flex justify-end space-x-3 opacity-80 group-hover:opacity-100 transition-opacity">
                                                        {u.role === 'student' ? (
                                                            <button
                                                                onClick={() => handleRoleUpdate(u.id, 'teacher')}
                                                                className="text-purple-400 hover:text-white bg-purple-500/10 hover:bg-purple-500 border border-transparent hover:border-purple-400/50 px-3 py-1.5 rounded-lg flex items-center transition-all shadow-sm"
                                                                title="Promote to Teacher"
                                                            >
                                                                <ArrowUpCircle className="w-4 h-4 mr-1.5" />
                                                                Promote
                                                            </button>
                                                        ) : (
                                                            <button
                                                                onClick={() => handleRoleUpdate(u.id, 'student')}
                                                                className="text-blue-400 hover:text-white bg-blue-500/10 hover:bg-blue-500 border border-transparent hover:border-blue-400/50 px-3 py-1.5 rounded-lg flex items-center transition-all shadow-sm"
                                                                title="Demote to Student"
                                                            >
                                                                <ArrowDownCircle className="w-4 h-4 mr-1.5" />
                                                                Demote
                                                            </button>
                                                        )}
                                                        <button
                                                            onClick={() => handleDeleteUser(u.id)}
                                                            className="text-red-400 hover:text-white bg-red-500/10 hover:bg-red-500 border border-transparent hover:border-red-400/50 p-1.5 rounded-lg flex items-center transition-all shadow-sm"
                                                            title="Delete User"
                                                        >
                                                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-trash-2"><path d="M3 6h18" /><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6" /><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2" /><line x1="10" x2="10" y1="11" y2="17" /><line x1="14" x2="14" y1="11" y2="17" /></svg>
                                                        </button>
                                                    </div>
                                                )}
                                            </td>
                                        </tr>
                                    ))}
                                    {filteredUsers.length === 0 && (
                                        <tr>
                                            <td colSpan="4" className="px-6 py-16 text-center text-indigo-300/50 font-medium">
                                                <div className="flex flex-col items-center justify-center">
                                                    <Search className="w-8 h-8 mb-3 opacity-50" />
                                                    No users found matching your search.
                                                </div>
                                            </td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                )}
            </main>

            {/* Create User Modal */}
            {createModalOpen && (
                <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50 transition-opacity">
                    <div className="bg-[#131B2F] rounded-3xl border border-indigo-500/20 shadow-[0_20px_50px_rgba(0,0,0,0.5)] max-w-md w-full p-8 relative overflow-hidden">
                        {/* Deco elements */}
                        <div className="absolute top-0 right-0 w-32 h-32 bg-red-500/10 rounded-full blur-3xl -mr-16 -mt-16 pointer-events-none"></div>

                        <div className="flex justify-between items-center mb-6 relative z-10">
                            <h2 className="text-2xl font-bold text-white tracking-tight">Create New User</h2>
                            <button
                                onClick={() => setCreateModalOpen(false)}
                                className="text-gray-400 hover:text-red-400 bg-white/5 hover:bg-red-500/10 p-2 rounded-xl transition-all"
                            >
                                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                            </button>
                        </div>
                        <form onSubmit={handleCreateUser} className="relative z-10">
                            <div className="space-y-5">
                                <div>
                                    <label className="block text-sm font-bold text-indigo-300 mb-2 uppercase tracking-wider">Username</label>
                                    <input
                                        type="text"
                                        required
                                        value={newUser.username}
                                        onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                                        className="w-full bg-[#0A0F1C]/80 border border-indigo-500/20 rounded-xl px-4 py-3 text-white focus:ring-2 focus:ring-red-500 focus:border-transparent outline-none transition-all shadow-inner font-medium"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-bold text-indigo-300 mb-2 uppercase tracking-wider">Email</label>
                                    <input
                                        type="email"
                                        required
                                        value={newUser.email}
                                        onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                                        className="w-full bg-[#0A0F1C]/80 border border-indigo-500/20 rounded-xl px-4 py-3 text-white focus:ring-2 focus:ring-red-500 focus:border-transparent outline-none transition-all shadow-inner font-medium"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-bold text-indigo-300 mb-2 uppercase tracking-wider">Password</label>
                                    <input
                                        type="password"
                                        required
                                        value={newUser.password}
                                        onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                                        className="w-full bg-[#0A0F1C]/80 border border-indigo-500/20 rounded-xl px-4 py-3 text-white focus:ring-2 focus:ring-red-500 focus:border-transparent outline-none transition-all shadow-inner font-medium"
                                    />
                                </div>
                                <div>
                                    <label className="block text-sm font-bold text-indigo-300 mb-2 uppercase tracking-wider">Role</label>
                                    <select
                                        value={newUser.role}
                                        onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                                        className="w-full bg-[#0A0F1C]/80 border border-indigo-500/20 rounded-xl px-4 py-3 text-white focus:ring-2 focus:ring-red-500 focus:border-transparent outline-none transition-all shadow-inner font-bold appearance-none cursor-pointer"
                                    >
                                        <option value="student">Student</option>
                                        <option value="teacher">Teacher</option>
                                        <option value="admin">Admin</option>
                                    </select>
                                </div>
                            </div>
                            <div className="mt-8 flex justify-end space-x-4">
                                <button
                                    type="button"
                                    onClick={() => setCreateModalOpen(false)}
                                    className="px-5 py-3 hover:bg-[#1A233A] text-gray-400 hover:text-white rounded-xl transition-colors font-bold border border-transparent hover:border-gray-700"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    className="px-6 py-3 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white rounded-xl transition-all font-bold shadow-[0_0_15px_rgba(239,68,68,0.3)] hover:scale-[1.02] active:scale-[0.98]"
                                >
                                    Create User
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
};

export default AdminDashboard;
