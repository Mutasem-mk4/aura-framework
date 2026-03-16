/**
 * Apex v2.0 Sentient Interceptor: Runtime Taint Tracking Hook
 * This script is injected into the browser by the OMEGA Crawler to monitor data flow.
 */

(function() {
    console.log("[🌀] Aura Taint Hook Active");

    const SINKS = ['eval', 'setTimeout', 'setInterval', 'Function', 'innerHTML', 'outerHTML', 'document.write'];
    const SOURCES = ['location.hash', 'location.search', 'document.referrer', 'window.name'];

    // 1. Hooking Sinks
    const originalEval = window.eval;
    window.eval = function(code) {
        console.warn(`[💀] TAINT DETECTED: eval() called with: ${code.substring(0, 100)}`);
        // Notify Aura via a custom header or log that the proxy will pick up
        fetch("/__aura_taint_log", {
            method: "POST",
            body: JSON.stringify({type: "sink_hit", sink: "eval", content: code})
        }).catch(() => {});
        return originalEval.apply(this, arguments);
    };

    // Hooking innerHTML
    const originalDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    Object.defineProperty(Element.prototype, 'innerHTML', {
        set: function(value) {
            if (typeof value === 'string' && (value.includes('<script') || value.includes('onerror='))) {
                console.warn(`[💀] TAINT DETECTED: innerHTML set with suspicious value: ${value.substring(0, 100)}`);
                fetch("/__aura_taint_log", {
                    method: "POST",
                    body: JSON.stringify({type: "sink_hit", sink: "innerHTML", content: value})
                }).catch(() => {});
            }
            return originalDescriptor.set.apply(this, arguments);
        }
    });

    // 2. Monitoring Sources
    window.addEventListener('hashchange', function() {
        console.log(`[🌀] SOURCE CHANGE: location.hash -> ${location.hash}`);
    });

})();
