import { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import api from '../api/axios';
import { ArrowLeft, AlertTriangle, CheckCircle, RefreshCw, Users, Download } from 'lucide-react';
import { saveAs } from 'file-saver';

const ExamDetails = () => {
    const { roomId } = useParams();
    const [sessions, setSessions] = useState([]); // List of { id, student, ... }
    const [selectedSessionId, setSelectedSessionId] = useState(null);
    const [logs, setLogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [autoRefresh, setAutoRefresh] = useState(true);
    const [viewLedgerMode, setViewLedgerMode] = useState(false);
    const [showCriticalOnly, setShowCriticalOnly] = useState(false);

    const navigate = useNavigate();

    // Derived state
    const selectedSession = sessions.find(s => s.id === selectedSessionId) || null;

    // Fetch list of students/sessions
    const fetchSessions = async () => {
        try {
            const response = await api.get(`/exams/room/${roomId}/students`);
            setSessions(response.data);
            setLoading(false);
        } catch (error) {
            console.error("Failed to fetch sessions", error);
        }
    };

    // Fetch logs for selected student
    const fetchLogs = async () => {
        if (!selectedSessionId) return;
        try {
            const params = {};
            if (viewLedgerMode) {
                params.source = 'ledger';
            }
            const response = await api.get(`/exams/${selectedSessionId}/logs`, { params });
            setLogs(response.data);
        } catch (error) {
            console.error("Failed to fetch logs", error);
        }
    };

    // Initial load and Polling
    // Keep a ref to sessions to use in interval without triggering re-renders/effect resets
    const sessionsRef = useRef(sessions);
    useEffect(() => {
        sessionsRef.current = sessions;
    }, [sessions]);

    // Initial load and Polling
    useEffect(() => {
        fetchSessions();
        const interval = setInterval(() => {
            fetchSessions(); // Always update session list to see new students/status changes

            // Auto-refresh logs only if:
            // 1. Auto-refresh is enabled
            // 2. We are NOT looking at static ledger logs
            // 3. A session is selected
            // 4. The session is NOT completed (check ref for latest data)
            if (autoRefresh && !viewLedgerMode && selectedSessionId) {
                const currentSession = sessionsRef.current.find(s => s.id === selectedSessionId);
                if (currentSession && !currentSession.end_time) {
                    fetchLogs();
                }
            }
        }, 1000);
        return () => clearInterval(interval);
    }, [roomId, selectedSessionId, autoRefresh, viewLedgerMode]); // Removed selectedSession/sessions from deps

    // Fetch logs immediately when selection changes or mode changes
    useEffect(() => {
        if (selectedSessionId) {
            setLogs([]); // Clear previous logs
            setShowCriticalOnly(false); // Reset filter
            fetchLogs();
        }
    }, [selectedSessionId, viewLedgerMode]);

    const handleExport = async () => {
        try {
            const response = await api.get(`/exams/room/${roomId}/export_csv`, {
                responseType: 'blob',
            });
            const blob = new Blob([response.data], { type: 'text/csv' });
            saveAs(blob, `exam_room_${roomId}_logs.csv`);
        } catch (error) {
            console.error("Export failed", error);
        }
    };

    return (
        <div className="min-h-screen bg-[#0A0F1C] bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-slate-900 via-[#0A0F1C] to-black text-white font-sans flex flex-col h-screen overflow-hidden selection:bg-blue-500/30">
            {/* Header */}
            <div className="border-b border-indigo-900/30 bg-[#0A0F1C]/70 backdrop-blur-xl p-4 flex justify-between items-center shadow-lg z-10">
                <div className="flex items-center space-x-4">
                    <button
                        onClick={() => navigate('/teacher')}
                        className="p-2 hover:bg-blue-500/10 rounded-full transition-colors text-indigo-300 hover:text-blue-400"
                    >
                        <ArrowLeft className="h-6 w-6" />
                    </button>
                    <div>
                        <h1 className="text-xl font-bold flex items-center bg-clip-text text-transparent bg-gradient-to-r from-white to-gray-400">
                            Exam Monitor <span className="ml-2 px-2 py-0.5 bg-blue-500/20 text-blue-400 text-sm rounded-md font-mono border border-blue-500/30">#{roomId}</span>
                        </h1>
                        <p className="text-xs text-indigo-200/60 mt-0.5 font-medium">
                            {sessions.length} Students Enrolled
                        </p>
                    </div>
                </div>
                <div className="flex items-center space-x-3">
                    <button
                        onClick={() => setAutoRefresh(!autoRefresh)}
                        disabled={viewLedgerMode || (selectedSession && selectedSession.end_time)}
                        className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-sm font-bold transition-all shadow-sm ${viewLedgerMode ? 'bg-[#131B2F]/60 text-gray-500 border border-gray-700/50 cursor-not-allowed' :
                            (selectedSession && selectedSession.end_time) ? 'bg-[#131B2F]/60 text-indigo-300/50 border border-indigo-500/10 cursor-not-allowed' :
                                autoRefresh ? 'bg-green-500/10 text-green-400 border border-green-500/30 shadow-[0_0_10px_rgba(34,197,94,0.1)]' :
                                    'bg-[#131B2F]/60 text-gray-400 border border-indigo-500/10 hover:border-indigo-500/30'
                            }`}
                        title={selectedSession?.end_time ? "Session Completed" : "Toggle Auto-Refresh"}
                    >
                        {selectedSession?.end_time ? (
                            <CheckCircle className="h-4 w-4" />
                        ) : (
                            <RefreshCw className={`h-4 w-4 ${autoRefresh && !viewLedgerMode ? 'animate-spin text-green-400' : ''}`} />
                        )}
                        <span>
                            {selectedSession?.end_time ? 'Completed' :
                                viewLedgerMode ? 'Offline View' :
                                    autoRefresh ? 'Live' : 'Paused'}
                        </span>
                    </button>
                    <button
                        onClick={handleExport}
                        className="flex items-center space-x-2 px-4 py-1.5 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white rounded-lg text-sm font-bold transition-all shadow-[0_0_15px_rgba(37,71,244,0.4)] hover:scale-105 active:scale-95"
                    >
                        <Download className="h-4 w-4" />
                        <span>Export CSV</span>
                    </button>
                </div>
            </div>

            {/* Main Layout */}
            <div className="flex flex-1 overflow-hidden">

                {/* Left Sidebar: Student List */}
                <div className="w-1/3 min-w-[300px] max-w-[400px] bg-[#131B2F]/40 backdrop-blur-md border-r border-indigo-500/20 flex flex-col z-0">
                    <div className="p-4 border-b border-indigo-500/10 bg-[#0A0F1C]/50">
                        <h2 className="text-sm font-bold text-indigo-300 uppercase tracking-widest flex items-center">
                            <Users className="h-4 w-4 mr-2" /> Students
                        </h2>
                    </div>
                    <div className="flex-1 overflow-y-auto overflow-x-hidden custom-scrollbar">
                        {loading && sessions.length === 0 ? (
                            <div className="p-8 text-center">
                                <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500 mx-auto"></div>
                            </div>
                        ) : sessions.length === 0 ? (
                            <div className="p-8 text-center text-indigo-300/50 text-sm">
                                <p>No students have joined yet.</p>
                                <p className="mt-2 text-xs">Share the exam code with your students.</p>
                            </div>
                        ) : (
                            <ul className="divide-y divide-indigo-500/10">
                                {sessions.map((session) => (
                                    <li key={session.id}>
                                        <button
                                            onClick={() => setSelectedSessionId(session.id)}
                                            className={`w-full text-left p-4 transition-all border-l-4 ${selectedSessionId === session.id ? 'bg-blue-600/10 border-blue-500 shadow-[inset_0_0_20px_rgba(37,71,244,0.1)]' : 'border-transparent hover:bg-white/5'}`}
                                        >
                                            <div className="flex justify-between items-start">
                                                <div>
                                                    <p className={`font-bold ${selectedSessionId === session.id ? 'text-transparent bg-clip-text bg-gradient-to-r from-blue-300 to-purple-300' : 'text-gray-200'}`}>
                                                        {session.student?.username || 'Unknown'}
                                                    </p>
                                                    <p className="text-xs text-indigo-300/60 mt-0.5 truncate">{session.student?.email}</p>
                                                </div>
                                                <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold tracking-wider uppercase border shadow-sm ${session.end_time
                                                    ? 'bg-[#131B2F]/60 text-gray-400 border-gray-600'
                                                    : 'bg-green-500/10 text-green-400 border-green-500/30 shadow-[0_0_10px_rgba(34,197,94,0.1)]'
                                                    }`}>
                                                    {session.end_time ? 'Completed' : 'Active'}
                                                </span>
                                                {session.ledger_uploaded && (
                                                    <span className="ml-2 text-[10px] px-2 py-0.5 rounded-full font-bold tracking-wider uppercase border bg-purple-500/10 text-purple-400 border-purple-500/30 shadow-[0_0_10px_rgba(168,85,247,0.1)]" title="Ledger Uploaded">
                                                        Ledger
                                                    </span>
                                                )}
                                            </div>
                                            <p className="text-[10px] text-indigo-400/40 mt-2 font-mono">
                                                ID: {session.id}
                                            </p>
                                        </button>
                                    </li>
                                ))}
                            </ul>
                        )}
                    </div>
                </div>

                {/* Right Content: Student Logs */}
                <div className="flex-1 min-w-0 bg-transparent flex flex-col relative z-0">
                    {!selectedSession ? (
                        <div className="flex-1 flex flex-col items-center justify-center text-gray-500 p-8">
                            <div className="bg-gray-800 p-6 rounded-full mb-4">
                                <Users className="h-12 w-12 text-gray-600" />
                            </div>
                            <h3 className="text-xl font-medium text-gray-300">Select a Student</h3>
                            <p className="max-w-md text-center mt-2 text-gray-600">
                                Click on a student from the sidebar to view their real-time activity logs and security alerts.
                            </p>
                        </div>
                    ) : (
                        <>
                            {/* Selected Student Header */}
                            <div className="bg-[#131B2F]/60 backdrop-blur-md border-b border-indigo-500/20 px-6 py-4 flex justify-between items-center shadow-md">
                                <div>
                                    <h2 className="text-xl font-bold text-white flex items-center">
                                        {selectedSession.student?.username}
                                        <span className="ml-3 text-xs font-bold text-indigo-300/70 border border-indigo-500/30 px-3 py-1 rounded-full bg-indigo-500/5">
                                            {selectedSession.student?.email}
                                        </span>
                                    </h2>
                                </div>
                                <div className="flex items-center space-x-4">
                                    {selectedSession.ledger_uploaded && (
                                        <div className="flex items-center space-x-1 bg-[#0A0F1C]/80 rounded-lg p-1 border border-indigo-500/20 shadow-inner">
                                            <button
                                                onClick={() => setViewLedgerMode(false)}
                                                className={`text-xs px-4 py-1.5 rounded-md transition-all font-bold ${!viewLedgerMode ? 'bg-gradient-to-r from-blue-600 to-blue-500 text-white shadow-md' : 'text-gray-400 hover:text-white'}`}
                                            >
                                                Live Logs
                                            </button>
                                            <button
                                                onClick={() => setViewLedgerMode(true)}
                                                className={`text-xs px-4 py-1.5 rounded-md transition-all font-bold flex items-center ${viewLedgerMode ? 'bg-gradient-to-r from-purple-600 to-purple-500 text-white shadow-md' : 'text-gray-400 hover:text-white'}`}
                                            >
                                                <span>Ledger Logs</span>
                                                {viewLedgerMode && <CheckCircle className="w-3 h-3 ml-1.5" />}
                                            </button>
                                        </div>
                                    )}

                                    {selectedSession.ledger_uploaded && !viewLedgerMode && (
                                        <button
                                            onClick={async () => {
                                                try {
                                                    const response = await api.get(`/exams/${selectedSession.id}/export_logs_txt`, {
                                                        responseType: 'blob',
                                                    });
                                                    const blob = new Blob([response.data], { type: 'text/plain' });
                                                    saveAs(blob, `session_${selectedSession.id}_logs.txt`);
                                                } catch (error) {
                                                    console.error("Download failed", error);
                                                    alert("Failed to download logs.");
                                                }
                                            }}
                                            className="text-gray-400 hover:text-blue-400 transition-colors bg-[#131B2F]/50 p-2 rounded-lg border border-indigo-500/10 hover:border-blue-500/30"
                                            title="Download Decrypted Logs (TXT)"
                                        >
                                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-file-text"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /><line x1="10" y1="9" x2="8" y2="9" /></svg>
                                        </button>
                                    )}

                                    {viewLedgerMode && (
                                        <button
                                            onClick={() => setShowCriticalOnly(!showCriticalOnly)}
                                            className={`text-xs px-3 py-1.5 rounded-md transition-all flex items-center border font-bold ${showCriticalOnly
                                                ? 'bg-red-500/20 text-red-400 border-red-500/50 shadow-[0_0_10px_rgba(239,68,68,0.2)]'
                                                : 'bg-[#131B2F]/50 border-indigo-500/10 text-indigo-300 hover:text-white hover:border-indigo-500/30'
                                                }`}
                                            title={showCriticalOnly ? "Show All Logs" : "Show Critical Only"}
                                        >
                                            <AlertTriangle className="w-3 h-3 mr-1.5" />
                                            <span>Critical Only</span>
                                        </button>
                                    )}

                                    <div className="text-sm font-medium text-indigo-300/60 bg-[#0A0F1C]/50 px-3 py-1.5 rounded-lg border border-indigo-500/10">
                                        <span className={`font-mono font-bold ${viewLedgerMode ? 'text-purple-400' : 'text-blue-400'}`}>{logs.length}</span> Events Logged
                                    </div>
                                </div>
                            </div>

                            {/* Logs Stream */}
                            <div className="flex-1 overflow-y-auto p-6 space-y-3 custom-scrollbar">

                                {selectedSession.ledger_uploaded && !viewLedgerMode && (
                                    <div className="bg-purple-600/10 border border-purple-500/30 p-4 rounded-xl mb-6 flex items-center justify-between shadow-lg shadow-purple-900/20 backdrop-blur-sm">
                                        <div className="flex items-center">
                                            <div className="bg-purple-500/20 p-2 rounded-full mr-4">
                                                <CheckCircle className="w-6 h-6 text-purple-400" />
                                            </div>
                                            <div>
                                                <h4 className="font-bold text-lg text-purple-100">Exam Ledger Uploaded</h4>
                                                <p className="text-xs text-purple-300">
                                                    This student has completed the exam and verified their offline logs.
                                                    Switch to Ledger view to see the full, decrypted history including offline activity.
                                                </p>
                                            </div>
                                        </div>
                                        <button
                                            onClick={() => setViewLedgerMode(true)}
                                            className="bg-purple-600 hover:bg-purple-500 text-white px-5 py-2.5 rounded-lg text-sm font-bold shadow-md transition-all hover:scale-105"
                                        >
                                            View Ledger Logs
                                        </button>
                                    </div>
                                )}

                                {viewLedgerMode && (
                                    <div className="mb-4 p-3 bg-purple-500/10 border border-purple-500/20 rounded-lg text-purple-200 text-xs flex items-center">
                                        <AlertTriangle className="w-4 h-4 mr-2" />
                                        You are viewing verified offline logs from the student's encrypted ledger.
                                    </div>
                                )}
                                {logs.length === 0 ? (
                                    <div className="text-center py-20 text-indigo-300/50 font-medium">
                                        {viewLedgerMode ? "No logs found in the uploaded ledger." : "No activity recorded for this session yet."}
                                    </div>
                                ) : (
                                    logs.slice().reverse().filter(log => !showCriticalOnly || log.is_suspicious).map((log, index) => (
                                        <div
                                            key={index}
                                            className={`p-5 rounded-2xl border text-sm font-mono transition-all backdrop-blur-sm ${log.is_suspicious
                                                ? 'bg-red-500/10 border-red-500/30 text-red-200 shadow-[0_0_15px_rgba(239,68,68,0.1)]'
                                                : 'bg-[#131B2F]/50 border-indigo-500/10 text-gray-300 hover:border-blue-500/30 hover:bg-[#131B2F]/80'
                                                }`}
                                        >
                                            <div className="flex justify-between items-start mb-3">
                                                <div className="flex items-center space-x-3">
                                                    {log.is_suspicious ? (
                                                        <div className="bg-red-500/20 p-1.5 rounded-lg border border-red-500/30 shadow-[0_0_10px_rgba(239,68,68,0.2)]">
                                                            <AlertTriangle className="w-4 h-4 text-red-400" />
                                                        </div>
                                                    ) : (
                                                        <div className="bg-green-500/10 p-1.5 rounded-lg border border-green-500/20">
                                                            <CheckCircle className="w-4 h-4 text-green-400" />
                                                        </div>
                                                    )}
                                                    <span className={`px-2.5 py-1 rounded-md text-[10px] uppercase font-bold tracking-widest border ${log.log_type === 'alert' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                                                        log.log_type === 'process' ? 'bg-blue-500/20 text-blue-400 border-blue-500/30' :
                                                            log.log_type === 'url' ? 'bg-purple-500/20 text-purple-400 border-purple-500/30' :
                                                                'bg-gray-700/50 text-gray-400 border-gray-600'
                                                        }`}>
                                                        {log.log_type}
                                                    </span>
                                                    {log.source === 'ledger' && (
                                                        <span className="px-2.5 py-1 rounded-md text-[10px] uppercase font-bold tracking-widest bg-purple-500/20 text-purple-300 border border-purple-500/30 shadow-[0_0_10px_rgba(168,85,247,0.1)]">
                                                            OFFLINE
                                                        </span>
                                                    )}
                                                </div>
                                                <span className="text-gray-500 text-xs font-bold font-sans bg-black/20 px-3 py-1 rounded-lg border border-white/5">
                                                    {new Date(log.timestamp.endsWith('Z') ? log.timestamp : log.timestamp + 'Z').toLocaleTimeString()}
                                                </span>
                                            </div>
                                            <p className="break-all leading-relaxed opacity-90 text-sm mt-3 ml-2 font-medium">{log.content}</p>
                                        </div>
                                    ))
                                )}
                            </div>
                        </>
                    )}
                </div>
            </div>
        </div>
    );
};

export default ExamDetails;
