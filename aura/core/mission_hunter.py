import asyncio
import logging
from typing import List, Dict, Optional
from aura.modules.program_ranker import ProgramRanker
from aura.core import state

logger = logging.getLogger("aura")

class MissionHunter:
    """
    v40.0 OMEGA: The Mission Hunter.
    Automatically acquires high-yield bug bounty targets and dispatches scanning missions.
    """

    def __init__(self):
        self.ranker = ProgramRanker()
        self.active_missions = []
        self.blacklist = [] # Handles to skip

    async def identify_top_mission(self, platform: str = "all") -> Optional[Dict]:
        """Identifies the single best ROI program available."""
        try:
            programs = await self.ranker.get_ranked_programs(platform=platform)
            # Filter for pay-only and public
            eligible = [p for p in programs if p.get("max_bounty", 0) > 0 and p.get("handle") not in self.blacklist]
            
            if eligible:
                top = eligible[0]
                logger.info(f"[MissionHunter] Top Mission Identified: {top['name']} ({top['platform']}) - ROI: {top['roi_score']}")
                return top
        except Exception as e:
            logger.error(f"[MissionHunter] Failed to identify mission: {e}")
        return None

    def extract_initial_targets(self, program: Dict) -> List[str]:
        """
        Extracts valid seed URLs/domains from program metadata.
        v40.0: Fallback to platform-specific handle exploration.
        """
        handle = program.get("handle")
        platform = program.get("platform")
        
        # In a real scenario, this would scrape the program's 'Scope' page or use the API
        # For this implementation, we use a smart heuristic:
        # Most programs use handle.com or api.handle.com
        seeds = []
        if handle:
            seeds.append(f"{handle}.com")
            seeds.append(f"api.{handle}.com")
            seeds.append(f"staging.{handle}.com")
            seeds.append(f"dev.{handle}.com")
            
        return seeds

    async def dispatch_mission(self, orchestrator, program: Dict):
        """feeds a high-ROI mission into the NeuralOrchestrator."""
        targets = self.extract_initial_targets(program)
        if not targets:
            logger.warning(f"[MissionHunter] No targets found for {program['name']}")
            return

        logger.info(f"[MissionHunter] Dispatching Mission: {program['name']} | Targets: {len(targets)}")
        
        # We start with the primary domain
        primary = targets[0]
        
        # Set orchestrator state for the program
        orchestrator.current_mission = program
        
        # Run the advanced chain
        await orchestrator.execute_advanced_chain(primary, campaign_id=program.get("handle"), swarm_mode=True)

    async def run_eternal_hunt(self, orchestrator):
        """Eternal loop for continuous bounty hunting."""
        logger.info("[MissionHunter] Eternal Hunt Mode Activated. Payout optimization: ON.")
        
        while True:
            mission = await self.identify_top_mission()
            if mission:
                await self.dispatch_mission(orchestrator, mission)
                
                # After a mission, we add to temporary blacklist to ensure diversity
                self.blacklist.append(mission.get("handle"))
                if len(self.blacklist) > 10:
                    self.blacklist.pop(0)
            else:
                logger.info("[MissionHunter] No new high-ROI missions. Pulsing every 10 mins...")
                await asyncio.sleep(600)
            
            await asyncio.sleep(60) # Interval between mission dispatches

if __name__ == "__main__":
    # Test stub
    async def test():
        hunter = MissionHunter()
        top = await hunter.identify_top_mission()
        print(f"Top: {top}")
    
    asyncio.run(test())
