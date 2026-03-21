import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Terminal as TerminalIcon, 
  Activity, 
  Map as MapIcon, 
  DollarSign, 
  Zap,
  LayoutDashboard,
  Target,
  FileCode,
  Settings
} from 'lucide-react';
import { motion } from 'framer-motion';
import NeuralMap from './components/NeuralMap';
import KineticTerminal from './components/KineticTerminal';

const EventStream = ({ events }) => (
  <div className="p-4 flex flex-col gap-3 font-mono text-xs overflow-y-auto h-full scrollbar-none">
    {events.map((event, i) => (
      <motion.div 
        initial={{ opacity: 0, x: -10 }}
        animate={{ opacity: 1, x: 0 }}
        key={i} 
        className="flex gap-2 border-l border-white/10 pl-2"
      >
        <span className="text-white/30">{new Date().toLocaleTimeString()}</span>
        <span className={
          event.level === 'critical' ? 'text-red-500' : 
          event.level === 'warn' ? 'text-yellow-500' : 
          event.level === 'success' ? 'text-green-500' : 'text-sentient-cyan'
        }>[{event.content}]</span>
      </motion.div>
    ))}
  </div>
);

const ROIChart = () => (
  <div className="p-4 h-full flex flex-col gap-2">
    <div className="flex justify-between items-center text-[10px] uppercase text-white/40">
      <span>Target ROI Distribution</span>
      <DollarSign size={12} />
    </div>
    <div className="flex-1 flex items-end gap-2 pb-2">
      {[40, 70, 45, 90, 65, 80].map((h, i) => (
        <div key={i} className="flex-1 bg-gradient-to-t from-omega-neon/50 to-omega-neon rounded-t-sm" style={{ height: `${h}%` }}></div>
      ))}
    </div>
  </div>
);

function App() {
  const [events, setEvents] = useState([
    { content: 'OMEGA Engine Handshake: Success', level: 'info' },
  ]);
  const [findingsCount, setFindingsCount] = useState(6936);
  const [targetInput, setTargetInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });

  // WebSocket Connection
  useEffect(() => {
    const ws = new WebSocket('ws://localhost:8005/ws/stream');
    
    ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === 'finding') {
        setEvents(prev => [...prev.slice(-15), { content: msg.content, level: msg.level }]);
        // Update nodes for current target
        setGraphData(prev => {
           const newNode = { id: msg.data.type || 'vulnerability', group: 3, val: 15, color: '#ff0000' };
           return {
             nodes: [...prev.nodes, newNode],
             links: prev.nodes.length > 0 ? [...prev.links, { source: prev.nodes[0].id, target: newNode.id }] : prev.links
           };
        });
      } else if (msg.type === 'status') {
        setEvents(prev => [...prev.slice(-15), { content: msg.content, level: msg.level }]);
      } else if (msg.type === 'stats') {
        if (msg.data.findings) setFindingsCount(msg.data.findings);
      }
    };

    ws.onopen = () => console.log('Nexus WebSocket Connected');
    ws.onclose = () => console.log('Nexus WebSocket Disconnected');

    return () => ws.close();
  }, []);

  const handleStartMission = async (e) => {
    e.preventDefault();
    if (!targetInput) return;
    
    setIsScanning(true);
    setEvents(prev => [...prev, { content: `Initializing Tactical Mission: ${targetInput}`, level: 'info' }]);
    
    try {
      const response = await fetch('http://localhost:8005/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: targetInput })
      });
      if (!response.ok) throw new Error('API Handshake Failed');
      console.log('Mission Dispatched');
    } catch (err) {
      setEvents(prev => [...prev, { content: `Mission Failure: ${err.message}`, level: 'critical' }]);
    }
  };

  return (
    <div className="h-screen w-screen flex bg-aura-deep text-white overflow-hidden">
      {/* Sidebar Navigation */}
      <nav className="w-16 flex flex-col items-center py-6 gap-8 border-r border-white/5 bg-black/20">
        <div className="p-2 bg-omega-neon rounded-lg shadow-lg shadow-omega-neon/40">
          <Shield size={24} className="text-white" />
        </div>
        
        <div className="flex flex-col gap-6 mt-10 text-white/40">
          <LayoutDashboard size={20} className="hover:text-sentient-cyan cursor-pointer transition-colors" />
          <Target size={20} className="text-sentient-cyan cursor-pointer" />
          <FileCode size={20} className="hover:text-sentient-cyan cursor-pointer transition-colors" />
          <Activity size={20} className="hover:text-sentient-cyan cursor-pointer transition-colors" />
        </div>

        <div className="mt-auto">
          <Settings size={20} className="text-white/20 hover:text-white cursor-pointer transition-colors" />
        </div>
      </nav>

      {/* Main Command Center */}
      <main className="flex-1 flex flex-col p-4 gap-4 min-w-0">
        {/* Header Stats */}
        <header className="flex justify-between items-center px-2">
          <div className="flex flex-col">
            <h1 className="text-2xl font-bold tracking-tighter flex items-center gap-2 uppercase">
              Nexus Zenith <span className="text-[10px] bg-white/10 px-2 py-1 rounded text-white/50 font-mono">V3.0.0-PRO</span>
            </h1>
            <p className="text-[10px] text-sentient-cyan tracking-widest font-mono uppercase underline decoration-sentient-cyan/30">
              Tactical Deployment Command
            </p>
          </div>
          
          <div className="flex gap-4 items-center">
            <form onSubmit={handleStartMission} className="relative group">
              <input 
                type="text" 
                placeholder="TARGET DOMAIN (e.g. arc.net)" 
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                className="bg-black/40 border border-white/10 rounded-lg px-4 py-2 text-xs font-mono w-64 focus:outline-none focus:border-sentient-cyan/50 transition-all"
              />
              <button 
                type="submit"
                disabled={isScanning}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-sentient-cyan hover:text-white transition-colors disabled:opacity-50"
              >
                <Zap size={16} fill={isScanning ? "currentColor" : "none"} />
              </button>
            </form>
            <div className="glass-panel px-4 py-2 flex flex-col min-w-[100px]">
              <span className="text-[10px] text-white/40 uppercase">Findings</span>
              <span className="text-xl font-bold text-sentient-cyan">{findingsCount.toLocaleString()}</span>
            </div>
            <div className="glass-panel px-4 py-2 flex flex-col min-w-[100px]">
              <span className="text-[10px] text-white/40 uppercase">Active Threads</span>
              <span className="text-xl font-bold text-omega-neon">124</span>
            </div>
          </div>
        </header>

        {/* Content Grid */}
        <div className="flex-1 grid grid-cols-12 gap-4 h-full min-h-0">
          {/* Main Map Panel */}
          <div className="col-span-8 flex flex-col gap-4 min-h-0">
            <div className="flex-1 glass-panel overflow-hidden relative group">
              <div className="absolute top-4 left-4 z-10 flex gap-2">
                <div className="px-3 py-1 bg-sentient-cyan/20 border border-sentient-cyan/50 rounded-full text-[10px] text-sentient-cyan font-bold tracking-widest uppercase sentient-pulse">
                  {isScanning ? 'Synchronizing Intelligence...' : 'Live Field Map'}
                </div>
              </div>
              <NeuralMap data={graphData.nodes.length > 0 ? graphData : null} />
            </div>
            
            <div className="h-48 glass-panel overflow-hidden">
              <KineticTerminal />
            </div>
          </div>

          {/* Side Intelligence Panels */}
          <div className="col-span-4 flex flex-col gap-4 min-h-0">
            <div className="flex-1 glass-panel flex flex-col overflow-hidden">
              <div className="p-3 border-b border-white/5 flex justify-between items-center">
                <span className="text-[10px] font-bold tracking-widest uppercase text-white/60">Sentient Event Stream</span>
                <div className="w-1.5 h-1.5 rounded-full bg-red-500 animate-ping"></div>
              </div>
              <div className="flex-1 overflow-hidden">
                <EventStream events={events} />
              </div>
            </div>

            <div className="h-40 glass-panel">
              <ROIChart />
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;
