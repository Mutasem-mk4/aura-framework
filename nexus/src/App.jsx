import React, { useState, useEffect } from 'react';

const Dashboard = () => {
    const [targets, setTargets] = useState([]);
    const [stats, setStats] = useState({ vulns: 0, scanned: 0 });

    useEffect(() => {
        // Simulated fetch from FastAPI
        const fetchTargets = async () => {
            try {
                const res = await fetch('http://localhost:8000/targets');
                const data = await res.json();
                setTargets(data);
                setStats({ vulns: 12, scanned: data.length });
            } catch (e) {
                // Fallback for demo
                setTargets([
                    { id: 1, source: "Scan", type: "Domain", value: "example.com" },
                    { id: 2, source: "Analyze", type: "Subdomain", value: "staging.example.com" }
                ]);
            }
        };
        fetchTargets();
    }, []);

    return (
        <div className="min-h-screen p-8">
            {/* Header */}
            <div className="flex justify-between items-center mb-12">
                <div>
                    <h1 className="text-4xl font-bold bg-gradient-to-r from-aura-primary to-aura-secondary bg-clip-text text-transparent">
                        Aura Nexus v3.0
                    </h1>
                    <p className="text-gray-400 mt-2 italic">Zenith Singularity Command Center</p>
                </div>
                <div className="flex gap-4">
                    <div className="aura-glass p-4 rounded-xl text-center min-w-[120px]">
                        <p className="text-xs text-aura-primary uppercase tracking-widest mb-1">Targets</p>
                        <p className="text-2xl font-bold">{stats.scanned}</p>
                    </div>
                    <div className="aura-glass p-4 rounded-xl text-center min-w-[120px] aura-glow">
                        <p className="text-xs text-red-500 uppercase tracking-widest mb-1">Vulns</p>
                        <p className="text-2xl font-bold">{stats.vulns}</p>
                    </div>
                </div>
            </div>

            {/* Main Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Left: Intelligence Feed */}
                <div className="lg:col-span-2 space-y-6">
                    <h2 className="text-xl font-semibold flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-aura-secondary animate-pulse"></span>
                        Intelligence Feed
                    </h2>
                    <div className="aura-glass rounded-2xl overflow-hidden">
                        <table className="w-full text-left">
                            <thead className="bg-white/5 text-gray-400 text-sm uppercase tracking-wider">
                                <tr>
                                    <th className="px-6 py-4">ID</th>
                                    <th className="px-6 py-4">Source</th>
                                    <th className="px-6 py-4">Target</th>
                                    <th className="px-6 py-4">Status</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-white/5">
                                {targets.map(t => (
                                    <tr key={t.id} className="hover:bg-white/5 transition-colors cursor-pointer">
                                        <td className="px-6 py-4 font-mono text-aura-secondary">#{t.id}</td>
                                        <td className="px-6 py-4">{t.source}</td>
                                        <td className="px-6 py-4 font-bold">{t.value}</td>
                                        <td className="px-6 py-4">
                                            <span className="px-2 py-1 bg-green-500/10 text-green-500 text-xs rounded border border-green-500/20">Active</span>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>

                {/* Right: Visual Recon */}
                <div className="space-y-6">
                    <h2 className="text-xl font-semibold flex items-center gap-2">
                        Visual Intelligence
                    </h2>
                    <div className="grid grid-cols-1 gap-4">
                        <div className="aura-glass p-2 rounded-2xl">
                            <div className="aspect-video bg-aura-dark rounded-xl overflow-hidden border border-white/5 group relative">
                                <div className="absolute inset-0 bg-aura-primary/20 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                                    <button className="bg-aura-primary px-4 py-2 rounded-lg font-bold">View Screenshot</button>
                                </div>
                                <div className="p-4 text-center mt-8 text-gray-500 italic">No visual evidence found yet</div>
                            </div>
                            <p className="mt-4 text-sm px-2 text-gray-300">target_example.png - [passive]</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Dashboard;
