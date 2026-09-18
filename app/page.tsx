import React from 'react';
import { 
  ShieldAlert, 
  Terminal, 
  Activity, 
  Zap, 
  Skull, 
  Database, 
  Cpu,
  Search,
  ChevronRight
} from 'lucide-react';

// Mock data for initial states
const INITIAL_LOGS = [
  { id: 1, type: 'info', time: '10:42:01', msg: 'Sample: LLM-SEC orchestration trace; no engine connected.' },
  { id: 2, type: 'warn', time: '10:42:05', msg: 'Sample LangGraph nodes: [evaluator, generator, hitl_gate]' },
  { id: 3, type: 'error', time: '10:43:12', msg: 'Sample finding: Potential Excessive Agency in agent-bot-04' }
];

export default function Page() {
  const logs = INITIAL_LOGS;
  const riskScore = 68;

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-300 font-mono selection:bg-emerald-500/30">
      {/* --- HEADER / AI-SPM DASHBOARD --- */}
      <div className="bg-amber-500/90 text-zinc-950 text-xs font-bold tracking-widest px-4 py-1.5 text-center sticky top-0 z-50">
        Demo -- static sample data; no backend connected
      </div>
      <header className="border-b border-zinc-800 p-4 bg-zinc-900/50 flex items-center justify-between backdrop-blur-md">
        <div className="flex items-center gap-3">
          <div className="bg-emerald-500 p-1.5 rounded-sm">
            <Skull className="text-zinc-950 w-5 h-5" />
          </div>
          <h1 className="text-xl font-bold tracking-tighter text-zinc-100 uppercase">
            LLM-SEC <span className="text-emerald-500">Prototype</span>
          </h1>
        </div>

        <div className="flex gap-8 items-center">
          <div className="flex flex-col items-end">
            <span className="text-[10px] uppercase text-zinc-500">Sample Risk Posture</span>
            <span className={`text-xl font-bold ${riskScore > 70 ? 'text-rose-500' : 'text-amber-500'}`}>
              {riskScore}% CRITICAL
            </span>
          </div>
          <div className="h-10 w-px bg-zinc-800" />
          <div className="grid grid-cols-3 gap-4 text-center">
            <div>
              <p className="text-[10px] text-zinc-500 uppercase">Scans</p>
              <p className="font-bold text-zinc-200">1,204</p>
            </div>
            <div>
              <p className="text-[10px] text-zinc-500 uppercase">Breaches</p>
              <p className="font-bold text-rose-500">12</p>
            </div>
            <div>
              <p className="text-[10px] text-zinc-500 uppercase">Uptime</p>
              <p className="font-bold text-emerald-500">99.9%</p>
            </div>
          </div>
        </div>
      </header>

      <main className="p-4 grid grid-cols-12 gap-4 h-[calc(100vh-80px)]">
        
        {/* --- LEFT SIDEBAR: SCANNER HUB --- */}
        <aside className="col-span-2 flex flex-col gap-4">
          <div className="bg-zinc-900/40 border border-zinc-800 p-4 rounded-lg">
            <h2 className="text-[10px] uppercase font-bold text-zinc-500 mb-4 flex items-center gap-2">
              <Zap size={12} className="text-emerald-500" /> Scanner Hub
            </h2>
            <div className="flex flex-col gap-2">
              <button disabled title="Unavailable in demo" className="w-full text-left p-2 text-xs border border-zinc-700 rounded flex items-center justify-between opacity-50 cursor-not-allowed">
                PII Scanner <ChevronRight size={14} />
              </button>
              <button disabled title="Unavailable in demo" className="w-full text-left p-2 text-xs border border-zinc-700 rounded flex items-center justify-between opacity-50 cursor-not-allowed">
                Jailbreak Bench <ChevronRight size={14} />
              </button>
              <button disabled title="Unavailable in demo" className="w-full text-left p-2 text-xs border border-zinc-700 rounded flex items-center justify-between opacity-50 cursor-not-allowed">
                RAG Poisoning <ChevronRight size={14} />
              </button>
              <button disabled title="Unavailable in demo" className="w-full text-left p-2 text-xs border border-zinc-700 rounded flex items-center justify-between opacity-50 cursor-not-allowed mt-4">
                Generate AI-BOM <Database size={14} />
              </button>
            </div>
          </div>

          <div className="bg-zinc-900/40 border border-zinc-800 p-4 rounded-lg flex-grow">
             <h2 className="text-[10px] uppercase font-bold text-zinc-500 mb-4 flex items-center gap-2">
              <Activity size={12} className="text-emerald-500" /> Sample Metrics
            </h2>
            <div className="space-y-4">
              <MetricBar label="CPU Load" value={42} color="bg-emerald-500" />
              <MetricBar label="Token Flux" value={88} color="bg-amber-500" />
              <MetricBar label="Latency" value={12} color="bg-emerald-500" />
            </div>
          </div>
        </aside>

        {/* --- CENTER: ATTACK SURFACE MAPPER (LANGGRAPH VIS) --- */}
        <section className="col-span-7 bg-zinc-900/20 border border-zinc-800 rounded-lg relative overflow-hidden flex flex-col">
          <div className="absolute inset-0 opacity-10 pointer-events-none" 
               style={{ backgroundImage: 'radial-gradient(circle, #3f3f46 1px, transparent 1px)', backgroundSize: '20px 20px' }} />
          
          <div className="p-4 border-b border-zinc-800 flex justify-between items-center bg-zinc-900/60">
            <span className="text-xs font-bold uppercase tracking-widest text-zinc-400">Surface Mapper: LangGraph Visualizer</span>
            <span className="text-[10px] bg-zinc-700/60 text-zinc-400 px-2 py-0.5 rounded">STATIC DEMO</span>
          </div>

          <div className="flex-grow flex items-center justify-center">
            <div className="flex items-center gap-12">
              <GraphNode name="Attacker" icon={<Skull size={20}/>} status="active" color="emerald" />
              <div className="h-px w-16 bg-zinc-700 relative">
                <div className="absolute -top-1 right-0 w-2 h-2 border-t border-r border-zinc-700 rotate-45" />
              </div>
              <GraphNode name="Target LLM" icon={<Cpu size={20}/>} status="waiting" color="zinc" />
              <div className="h-px w-16 bg-zinc-700 relative">
                <div className="absolute -top-1 right-0 w-2 h-2 border-t border-r border-zinc-700 rotate-45" />
              </div>
              <GraphNode name="Evaluator" icon={<ShieldAlert size={20}/>} status="alert" color="rose" />
            </div>
          </div>

          {/* --- BOTTOM: TELEMETRY TERMINAL --- */}
          <footer className="h-1/3 border-t border-zinc-800 bg-black/80 p-4 font-mono text-[11px] overflow-y-auto">
            <div className="flex items-center gap-2 mb-2 text-zinc-500 border-b border-zinc-800 pb-1">
              <Terminal size={12} />
              <span>SAMPLE_REASONING_TRACE</span>
            </div>
            {logs.map((log) => (
              <div key={log.id} className="mb-1 leading-relaxed">
                <span className="text-zinc-600">[{log.time}]</span>{' '}
                <span className={log.type === 'error' ? 'text-rose-500' : log.type === 'warn' ? 'text-amber-500' : 'text-emerald-500'}>
                  {log.type.toUpperCase()}:
                </span>{' '}
                <span className="text-zinc-300">{log.msg}</span>
              </div>
            ))}
            <div className="text-emerald-500 animate-pulse">_</div>
          </footer>
        </section>

        {/* --- RIGHT SIDEBAR: AGENT MONITOR --- */}
        <aside className="col-span-3 flex flex-col gap-4">
          <div className="bg-zinc-900/40 border border-zinc-800 p-4 rounded-lg flex-grow overflow-y-auto">
            <h2 className="text-[10px] uppercase font-bold text-zinc-500 mb-4 flex items-center gap-2">
              <Search size={12} className="text-emerald-500" /> Sample Agents
            </h2>
            <div className="space-y-3">
              <AgentCard name="red-bot-01" task="Jailbreak: Crescendo" status="Running" />
              <AgentCard name="red-bot-02" task="Fuzzing: Energy" status="Standby" />
              <AgentCard name="red-bot-03" task="PII Extraction" status="Completed" />
              <AgentCard name="red-bot-04" task="Excessive Agency" status="VIOLATION" isCritical />
            </div>
          </div>
        </aside>
      </main>
    </div>
  );
}

const MetricBar = ({ label, value, color }: { label: string, value: number, color: string }) => (
  <div className="space-y-1">
    <div className="flex justify-between text-[10px] uppercase">
      <span>{label}</span>
      <span className="text-zinc-500">{value}%</span>
    </div>
    <div className="h-1 bg-zinc-800 rounded-full overflow-hidden">
      <div className={`h-full ${color} transition-all duration-1000`} style={{ width: `${value}%` }} />
    </div>
  </div>
);

const GraphNode = ({ name, icon, status, color }: { name: string, icon: React.ReactNode, status: string, color: string }) => (
  <div className="flex flex-col items-center gap-2 group">
    <div className={`p-4 rounded-full border-2 transition-all duration-300 ${color === 'emerald' ? 'bg-emerald-500/10 border-emerald-500 shadow-[0_0_15px_rgba(16,185,129,0.3)]' : color === 'rose' ? 'bg-rose-500/10 border-rose-500 animate-pulse shadow-[0_0_15px_rgba(244,63,94,0.3)]' : 'bg-zinc-800 border-zinc-700 text-zinc-500'}`}>
      {icon}
    </div>
    <span className="text-[10px] font-bold uppercase tracking-tighter">{name}</span>
    <span className={`text-[8px] uppercase px-1 rounded ${status === 'active' ? 'bg-emerald-500/20 text-emerald-500' : 'bg-zinc-800 text-zinc-500'}`}>{status}</span>
  </div>
);

const AgentCard = ({ name, task, status, isCritical }: { name: string, task: string, status: string, isCritical?: boolean }) => (
  <div className={`p-3 rounded border transition-all ${isCritical ? 'bg-rose-500/5 border-rose-500/40' : 'bg-zinc-800/40 border-zinc-700/50 hover:border-zinc-500'}`}>
    <div className="flex justify-between items-start mb-2">
      <span className="text-xs font-bold text-zinc-100">{name}</span>
      <span className={`text-[9px] uppercase font-bold ${isCritical ? 'text-rose-500' : 'text-emerald-500'}`}>● {status}</span>
    </div>
    <p className="text-[10px] text-zinc-500">Task: {task}</p>
  </div>
);