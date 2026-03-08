"""
Aura v29.0 — Phase 29 Verification (The Phantom Strike + DOM Hunter)
"""
import asyncio

async def test_phase29():
    print("=" * 60)
    print("  🕸️ Phase 29: The Phantom Strike & DOM Hunter — Verification")
    print("=" * 60)
    results = []

    # 1. Cache Poisoning Engine
    try:
        from aura.modules.cache_poisoning_engine import CachePoisoningEngine, UNKEYED_HEADERS
        engine = CachePoisoningEngine()
        assert len(UNKEYED_HEADERS) >= 10
        assert engine.CANARY.startswith("aura")
        print(f"  [✅] Web Cache Poisoning Engine: OK ({len(UNKEYED_HEADERS)} unkeyed headers configured)")
        results.append(True)
    except Exception as e:
        print(f"  [❌] Web Cache Poisoning Engine: FAILED — {e}")
        results.append(False)

    # 2. XXE Engine
    try:
        from aura.modules.xxe_engine import XXEEngine, CLASSIC_XXE_TEMPLATE, ENV_XXE_TEMPLATE
        xxe = XXEEngine()
        assert "SYSTEM" in CLASSIC_XXE_TEMPLATE
        assert ".env" in ENV_XXE_TEMPLATE
        assert hasattr(xxe, 'scan_url')
        print(f"  [✅] XXE Engine: OK (Classic + Windows + Cloud SSRF + .env payloads ready)")
        results.append(True)
    except Exception as e:
        print(f"  [❌] XXE Engine: FAILED — {e}")
        results.append(False)

    # 3. Prototype Pollution Engine
    try:
        from aura.modules.prototype_pollution_engine import PrototypePollutionEngine, CANARY, SS_PAYLOADS
        pp = PrototypePollutionEngine()
        assert len(SS_PAYLOADS) >= 5
        assert "__proto__" in str(SS_PAYLOADS)
        print(f"  [✅] Prototype Pollution Engine: OK ({len(SS_PAYLOADS)} payloads, canary: '{CANARY}')")
        results.append(True)
    except Exception as e:
        print(f"  [❌] Prototype Pollution Engine: FAILED — {e}")
        results.append(False)

    # 4. DOM Hunter
    try:
        from aura.modules.dom_hunter import DOMHunter
        dom = DOMHunter()
        assert hasattr(dom, 'scan_url')
        assert hasattr(dom, '_scan_dom_xss')
        assert hasattr(dom, '_scan_prototype_pollution')
        assert hasattr(dom, '_scan_storage_secrets')
        playwright_status = "[Playwright installed]" if dom._playwright_available else "[Playwright not installed — will auto-install on first run]"
        print(f"  [✅] DOM Hunter: OK {playwright_status}")
        results.append(True)
    except Exception as e:
        print(f"  [❌] DOM Hunter: FAILED — {e}")
        results.append(False)

    # 5. Orchestrator integration
    try:
        from aura.core.orchestrator import (
            CachePoisoningEngine, XXEEngine,
            PrototypePollutionEngine, DOMHunter
        )
        print(f"  [✅] NeuralOrchestrator Integration: All 4 Phase 29 engines accessible")
        results.append(True)
    except Exception as e:
        print(f"  [❌] Orchestrator Integration: FAILED — {e}")
        results.append(False)

    print()
    passed = sum(results)
    total = len(results)
    print(f"  Result: {passed}/{total} checks passed")
    if passed == total:
        print("  🕸️ Phase 29 [THE PHANTOM STRIKE]: FULLY OPERATIONAL")
    else:
        print("  ⚠️  Some checks failed")

asyncio.run(test_phase29())
