import { useState } from 'react';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';
import { LogOut, GraduationCap, ArrowRight, Download, CheckCircle } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import JSZip from 'jszip';
import { saveAs } from 'file-saver';

const StudentDashboard = () => {
    const [roomCode, setRoomCode] = useState('');
    const [password, setPassword] = useState('');
    const [session, setSession] = useState(null);
    const [error, setError] = useState('');
    const [joining, setJoining] = useState(false);
    const { user, logout } = useAuth();
    const navigate = useNavigate();

    const handleJoin = async (e) => {
        e.preventDefault();
        if (!roomCode) return;
        setJoining(true);
        setError('');

        try {
            // Join endpoint
            const response = await api.post(`/exams/join/${roomCode}`, { password });
            // If successful, we get session_id
            setSession(response.data);
            // We might want to persist session state
        } catch (err) {
            setError(err.response?.data?.detail || "Failed to join exam");
        } finally {
            setJoining(false);
        }
    };

    const handleLogout = async () => {
        if (session) {
            try {
                // Attempt to notify backend of exit
                await api.post(`/exams/leave/${session.session_id}`);
            } catch (err) {
                console.error("Failed to auto-exit exam on logout", err);
            }
        }
        logout();
        navigate('/login');
    };

    const handleDownload = async () => {
        if (!session) return;

        try {
            const zip = new JSZip();

            // 1. Generate Config JSON
            const config = {
                api_url: "http://localhost:8000",
                jwt_token: sessionStorage.getItem('token'),
                session_id: session.session_id,
                username: user?.sub
            };
            zip.file("monitor_config.json", JSON.stringify(config, null, 2));

            // 2. Fetch Monitor Executable (Bust cache to ensure latest version is downloaded)
            const exeResponse = await fetch(`/static/monitor.exe?t=${new Date().getTime()}`);
            if (!exeResponse.ok) throw new Error("Failed to fetch monitor executable");
            const exeBlob = await exeResponse.blob();
            zip.file("monitor.exe", exeBlob);

            // 3. Generate ZIP
            const content = await zip.generateAsync({ type: "blob" });
            saveAs(content, `exam_monitor_${user?.sub}_session_${session.session_id}.zip`);

            alert("Download started! Extract the ZIP and run 'monitor.exe' from the folder.");
        } catch (err) {
            console.error(err);
            alert("Failed to bundle download: " + err.message);
        }
    }

    const handleLeave = async () => {
        if (!session) return;
        if (!window.confirm("Are you sure you want to exit the exam? This will mark your session as completed.")) return;

        try {
            await api.post(`/exams/leave/${session.session_id}`);
            // Clear session and reset state
            setSession(null);
            setRoomCode('');
            alert("You have exited the exam.");
        } catch (err) {
            console.error("Failed to leave exam", err);
            alert("Failed to exit exam properly, but you can close the window.");
            setSession(null); // Force exit on frontend anyway
        }
    };

    return (
        <div className="min-h-screen bg-[#0A0F1C] bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-slate-900 via-[#0A0F1C] to-black text-white font-sans selection:bg-blue-500/30">
            {/* Navbar */}
            <nav className="border-b border-indigo-900/30 bg-[#0A0F1C]/70 backdrop-blur-xl sticky top-0 z-50 shadow-lg">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between items-center h-16">
                        <div className="flex items-center space-x-3">
                            <div className="bg-gradient-to-br from-blue-500 to-indigo-600 p-2.5 rounded-xl shadow-[0_0_15px_rgba(37,71,244,0.3)] border border-blue-400/20">
                                <GraduationCap className="h-6 w-6 text-white" />
                            </div>
                            <span className="text-xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-white to-gray-400">Student Portal</span>
                        </div>
                        <div className="flex items-center space-x-4">
                            <div className="text-sm font-medium text-indigo-200/60 hidden sm:block">
                                Logged in as <span className="text-blue-300 font-bold">{user?.sub}</span>
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

            <main className="max-w-4xl mx-auto px-4 py-12">
                {!session ? (
                    <div className="flex flex-col items-center justify-center space-y-8 relative z-10">
                        <div className="text-center max-w-lg mb-4">
                            <h1 className="text-4xl font-bold text-white mb-4 tracking-tight drop-shadow-lg text-transparent bg-clip-text bg-gradient-to-b from-white to-gray-400">Join an Exam</h1>
                            <p className="text-indigo-200/60 text-lg">Enter the room code provided by your instructor to start your secured examination session.</p>
                        </div>

                        <div className="w-full max-w-md bg-[#131B2F]/60 backdrop-blur-md p-8 rounded-3xl border border-indigo-500/10 shadow-[0_8px_30px_rgb(0,0,0,0.12)] hover:shadow-[0_8px_30px_rgba(37,71,244,0.15)] transition-all duration-500 relative overflow-hidden group">
                             {/* Glass reflection effect */}
                             <div className="absolute inset-0 bg-gradient-to-br from-white/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"></div>

                            <form onSubmit={handleJoin} className="space-y-6 relative z-10">
                                <div>
                                    <label className="block text-sm font-bold text-indigo-300 mb-2 uppercase tracking-wider">Room Code</label>
                                    <input
                                        type="text"
                                        required
                                        value={roomCode}
                                        onChange={(e) => setRoomCode(e.target.value.toUpperCase())}
                                        className="block w-full text-center text-3xl font-mono tracking-[0.3em] py-4 bg-[#0A0F1C]/80 border border-indigo-500/20 rounded-xl text-blue-400 font-bold focus:ring-2 focus:ring-blue-500 focus:border-transparent uppercase placeholder-indigo-900/50 shadow-inner transition-all"
                                        placeholder="XB3K9L"
                                        maxLength={6}
                                    />
                                </div>

                                <div>
                                    <label className="block text-sm font-bold text-indigo-300 mb-2 uppercase tracking-wider">Password</label>
                                    <input
                                        type="password"
                                        required
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        className="block w-full py-3 px-4 bg-[#0A0F1C]/80 border border-indigo-500/20 rounded-xl text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent placeholder-indigo-900/50 shadow-inner transition-all font-medium"
                                        placeholder="Enter exam password"
                                    />
                                </div>

                                {error && <p className="text-red-400 text-sm text-center font-bold bg-red-500/10 py-2 rounded-lg border border-red-500/20">{error}</p>}

                                <button
                                    type="submit"
                                    disabled={joining || !roomCode}
                                    className={`w-full py-4 rounded-xl font-bold flex justify-center items-center transition-all duration-300 ${!roomCode ? 'bg-[#131B2F]/60 text-gray-500 border border-gray-700/50 cursor-not-allowed' : 'bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white shadow-[0_0_20px_rgba(37,71,244,0.4)] hover:scale-[1.02] active:scale-[0.98]'}`}
                                >
                                    {joining ? 'Joining...' : <>Join Session <ArrowRight className="ml-2 w-5 h-5" /></>}
                                </button>
                            </form>
                        </div>
                    </div>
                ) : (
                    <div className="max-w-2xl mx-auto relative z-10">
                        <div className="bg-[#131B2F]/60 backdrop-blur-xl border border-indigo-500/20 p-8 rounded-3xl shadow-[0_8px_30px_rgb(0,0,0,0.12)] text-center relative overflow-hidden group">
                             {/* Glass reflection effect */}
                             <div className="absolute inset-0 bg-gradient-to-br from-white/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"></div>
                             
                            <div className="mx-auto bg-green-500/10 w-20 h-20 rounded-full flex items-center justify-center mb-6 shadow-[0_0_25px_rgba(34,197,94,0.2)] border border-green-500/20 relative z-10">
                                <CheckCircle className="w-10 h-10 text-green-400" />
                            </div>

                            <h2 className="text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-white to-gray-300 mb-2 relative z-10">Successfully Joined!</h2>
                            <p className="text-indigo-200/60 mb-8 relative z-10">Session ID: <span className="font-mono text-blue-400 font-bold bg-blue-500/10 px-2 py-1 rounded-md border border-blue-500/20">#{session.session_id}</span></p>

                            <div className="space-y-5 relative z-10">
                                <div className="bg-[#0A0F1C]/50 rounded-2xl p-6 border border-indigo-500/10 text-left shadow-inner">
                                    <h3 className="text-lg font-bold text-white mb-3 flex items-center">
                                        <div className="w-2 h-2 rounded-full bg-blue-500 mr-2 shadow-[0_0_8px_rgba(59,130,246,0.8)]"></div>
                                        Next Steps:
                                    </h3>
                                    <ol className="list-decimal list-inside space-y-3 text-indigo-100/70 font-medium">
                                        <li><span className="text-gray-300">Download the Exam Monitor token below.</span></li>
                                        <li><span className="text-gray-300">Run the executable file.</span></li>
                                        <li><span className="text-gray-300">The monitor will verify your environment and connect automatically.</span></li>
                                        <li><span className="text-red-300">Do not close the monitor until the exam is finished.</span></li>
                                    </ol>
                                </div>

                                <button
                                    onClick={handleDownload}
                                    className="w-full py-4 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white rounded-xl font-bold text-lg flex items-center justify-center shadow-[0_0_20px_rgba(37,71,244,0.3)] hover:scale-[1.02] active:scale-[0.98] transition-all"
                                >
                                    <Download className="w-6 h-6 mr-2" />
                                    Download Exam Monitor
                                </button>

                                <div className="mt-8 pt-8 border-t border-indigo-500/10">
                                    <h3 className="text-lg font-bold text-white mb-2">Exam Completion</h3>
                                    <p className="text-indigo-300/60 text-sm mb-6 font-medium">
                                        When you are finished with the exam, you must upload the encrypted ledger file generated by the monitor.
                                    </p>

                                    <label className="w-full py-4 bg-gradient-to-r from-[#131B2F] to-[#0A0F1C] border border-indigo-500/30 hover:border-blue-400/50 text-white rounded-xl font-bold text-lg flex items-center justify-center shadow-[0_0_15px_rgba(0,0,0,0.3)] hover:shadow-[0_0_20px_rgba(37,71,244,0.2)] transition-all cursor-pointer group hover:scale-[1.02]">
                                        <input
                                            type="file"
                                            accept=".enc"
                                            className="hidden"
                                            onChange={async (e) => {
                                                const file = e.target.files[0];
                                                if (!file) return;

                                                if (!window.confirm(`Upload ${file.name} and finish exam?`)) return;

                                                const formData = new FormData();
                                                formData.append('file', file);

                                                try {
                                                    const response = await api.post(`/exams/${session.session_id}/upload_ledger`, formData);
                                                    alert(`Ledger uploaded successfully! ${response.data.logs_imported} logs imported.`);
                                                    await handleLeave();
                                                } catch (err) {
                                                    console.error(err);
                                                    alert("Failed to upload ledger: " + (err.response?.data?.detail || err.message));
                                                }
                                            }}
                                        />
                                        <div className="bg-blue-500/20 p-2 rounded-lg mr-3 group-hover:bg-blue-500/30 transition-colors">
                                            <CheckCircle className="w-5 h-5 text-blue-400" />
                                        </div>
                                        Upload Ledger & Finish
                                    </label>

                                    <button
                                        onClick={handleLeave}
                                        className="w-full mt-6 py-2 text-red-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg text-sm font-bold transition-colors"
                                    >
                                        Emergency Exit (Without Upload)
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                )}
            </main>
        </div>
    );
};

export default StudentDashboard;
