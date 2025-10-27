import asyncio
from core.logger import log

class WorkflowExecutor:
    def __init__(self, orchestrator):
        self.orchestrator = orchestrator
        self.agent_registry = orchestrator.agent_registry
        self.context_manager = orchestrator.context_manager

    async def execute_campaign(self):
        """The main execution loop for the attack campaign."""
        try:
            campaign_goal = "Achieve root/administrator access on the target system." # Default goal

            while True:
                log.phase("Requesting next strategies from StrategyBuilder...")

                strategy_builder_agent_class = self.agent_registry.get_agent_class("StrategyBuilder")
                if not strategy_builder_agent_class:
                    log.critical("StrategyBuilder agent not found. Aborting attack run.")
                    break

                strategy_builder_agent = strategy_builder_agent_class(context_manager=self.context_manager, orchestrator=self.orchestrator)

                strategies_to_execute = await strategy_builder_agent.run(campaign_goal=campaign_goal)

                if not strategies_to_execute:
                    log.info("StrategyBuilder returned no strategies. Campaign might be complete or stalled.")
                    break

                if strategies_to_execute:
                    log.info(f"Executing {len(strategies_to_execute.generated_strategies)} strategies in parallel...")
                    tasks = [self.orchestrator._execute_agent(strategy) for strategy in strategies_to_execute.generated_strategies]
                    reports = await asyncio.gather(*tasks)

                    if any(not report or not report.success for report in reports):
                        log.warning("One or more agents failed in the parallel execution batch. Re-consulting StrategyBuilder.")
                        pass

                await asyncio.sleep(1)

            log.phase("Attack campaign concluded.")

        except KeyboardInterrupt:
            log.warning("Attack run interrupted by user.")
        except Exception as e:
            log.critical(f"A critical error occurred in the main loop: {e}", exc_info=True)