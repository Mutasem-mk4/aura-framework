import React, { useEffect, useRef } from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import 'xterm/css/xterm.css';

const KineticTerminal = () => {
    const terminalRef = useRef(null);
    const xtermRef = useRef(null);

    useEffect(() => {
        const term = new Terminal({
            cursorBlink: true,
            theme: {
                background: 'transparent',
                foreground: '#00FFFF',
                cursor: '#BF00FF',
                selectionBackground: 'rgba(191, 0, 255, 0.3)',
            },
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: 13,
            letterSpacing: 0.5,
        });

        const fitAddon = new FitAddon();
        term.loadAddon(fitAddon);

        term.open(terminalRef.current);
        fitAddon.fit();

        term.writeln('\x1b[1;35m[AURA OMEGA] Kinetic Terminal Stream Initialized...\x1b[0m');
        term.writeln('\x1b[36mConnected to Nexus Bridge v25.0\x1b[0m');
        term.write('\r\naura@nexus_zenith:~$ ');

        xtermRef.current = term;

        const handleResize = () => fitAddon.fit();
        window.addEventListener('resize', handleResize);

        return () => {
            window.removeEventListener('resize', handleResize);
            term.dispose();
        };
    }, []);

    return (
        <div className="w-full h-full bg-black/40 p-2 overflow-hidden">
            <div ref={terminalRef} className="w-full h-full" />
        </div>
    );
};

export default KineticTerminal;
