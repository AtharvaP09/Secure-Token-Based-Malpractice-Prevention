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
        <div className="min-h-screen bg-gray-900 text-white font-sans">
            {/* Navbar */}
            <nav className="border-b border-gray-800 bg-gray-900/50 backdrop-blur-md sticky top-0 z-50">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between items-center h-16">
                        <div className="flex items-center space-x-3">
                            <div className="bg-purple-600 p-2 rounded-lg shadow-lg shadow-purple-600/20">
                                <GraduationCap className="h-6 w-6 text-white" />
                            </div>
                            <span className="text-xl font-bold tracking-tight">Student Portal</span>
                        </div>
                        <div className="flex items-center space-x-4">
                            <div className="text-sm text-gray-400">
                                Logged in as <span className="text-gray-200 font-medium">{user?.sub}</span>
                            </div>
                            <button
                                onClick={handleLogout}
                                className="p-2 rounded-lg hover:bg-red-500/10 text-gray-400 hover:text-red-400 transition-colors"
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
                    <div className="flex flex-col items-center justify-center space-y-8">
                        <div className="text-center max-w-lg">
                            <h1 className="text-4xl font-bold text-white mb-4">Join an Exam</h1>
                            <p className="text-gray-400 text-lg">Enter the room code provided by your instructor to start your secured examination session.</p>
                        </div>

                        <div className="w-full max-w-md bg-gray-800 p-8 rounded-2xl border border-gray-700 shadow-2xl">
                            <form onSubmit={handleJoin} className="space-y-6">
                                <div>
                                    <label className="block text-sm font-medium text-gray-400 mb-2">Room Code</label>
                                    <input
                                        type="text"
                                        required
                                        value={roomCode}
                                        onChange={(e) => setRoomCode(e.target.value.toUpperCase())}
                                        className="block w-full text-center text-2xl font-mono tracking-widest py-3 bg-gray-900 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-purple-500 focus:border-transparent uppercase placeholder-gray-600"
                                        placeholder="XB3K9L"
                                        maxLength={6}
                                    />
                                </div>

                                <div>
                                    <label className="block text-sm font-medium text-gray-400 mb-2">Password</label>
                                    <input
                                        type="password"
                                        required
                                        value={password}
                                        onChange={(e) => setPassword(e.target.value)}
                                        className="block w-full py-3 px-4 bg-gray-900 border border-gray-600 rounded-lg text-white focus:ring-2 focus:ring-purple-500 focus:border-transparent placeholder-gray-600 transition-colors"
                                        placeholder="Enter exam password"
                                    />
                                </div>

                                {error && <p className="text-red-400 text-sm text-center">{error}</p>}

                                <button
                                    type="submit"
                                    disabled={joining || !roomCode}
                                    className={`w-full py-3 rounded-lg font-bold flex justify-center items-center transition-all ${!roomCode ? 'bg-gray-700 text-gray-500 cursor-not-allowed' : 'bg-purple-600 hover:bg-purple-700 text-white shadow-lg shadow-purple-600/25'}`}
                                >
                                    {joining ? 'Joining...' : <>Join Session <ArrowRight className="ml-2 w-5 h-5" /></>}
                                </button>
                            </form>
                        </div>
                    </div>
                ) : (
                    <div className="max-w-2xl mx-auto">
                        <div className="bg-gradient-to-br from-gray-800 to-gray-900 border border-gray-700 p-8 rounded-2xl shadow-2xl text-center">
                            <div className="mx-auto bg-green-500/10 w-16 h-16 rounded-full flex items-center justify-center mb-6">
                                <CheckCircle className="w-8 h-8 text-green-500" />
                            </div>

                            <h2 className="text-3xl font-bold text-white mb-2">Successfully Joined!</h2>
                            <p className="text-gray-400 mb-8">Session ID: <span className="font-mono text-purple-400">#{session.session_id}</span></p>

                            <div className="space-y-4">
                                <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700 text-left">
                                    <h3 className="text-lg font-semibold text-white mb-2">Next Steps:</h3>
                                    <ol className="list-decimal list-inside space-y-2 text-gray-300">
                                        <li>Download the Exam Monitor token below.</li>
                                        <li>Run the executable file.</li>
                                        <li>The monitor will verify your environment and connect automatically.</li>
                                        <li>Do not close the monitor until the exam is finished.</li>
                                    </ol>
                                </div>

                                <button
                                    onClick={handleDownload}
                                    className="w-full py-4 bg-purple-600 hover:bg-purple-700 text-white rounded-xl font-bold text-lg flex items-center justify-center shadow-lg shadow-purple-600/25 hover:shadow-purple-600/40 transition-all"
                                >
                                    <Download className="w-6 h-6 mr-2" />
                                    Download Exam Monitor
                                </button>

                                <div className="mt-8 pt-6 border-t border-gray-700">
                                    <h3 className="text-lg font-semibold text-white mb-4">Exam Completion</h3>
                                    <p className="text-gray-400 text-sm mb-4">
                                        When you are finished with the exam, you must upload the encrypted ledger file generated by the monitor (e.g., exam_ledger_username_session_123_exam.enc).
                                    </p>

                                    <label className="w-full py-4 bg-blue-600 hover:bg-blue-700 text-white rounded-xl font-bold text-lg flex items-center justify-center shadow-lg shadow-blue-600/25 hover:shadow-blue-600/40 transition-all cursor-pointer">
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
                                        <CheckCircle className="w-6 h-6 mr-2" />
                                        Upload Ledger & Finish
                                    </label>

                                    <button
                                        onClick={handleLeave}
                                        className="w-full mt-4 py-2 text-red-500 hover:text-red-400 text-sm font-medium transition-colors"
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
