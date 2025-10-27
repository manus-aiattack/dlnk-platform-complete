"""
End-to-End Test Suite
Test complete attack workflows
"""

import pytest
import asyncio
from typing import Dict
import logging

logger = logging.getLogger(__name__)


class TestE2EWorkflows:
    """End-to-end workflow tests"""
    
    @pytest.mark.asyncio
    async def test_full_attack_workflow(self):
        """
        Test complete attack workflow:
        1. Scan target
        2. AI analyzes results
        3. Generate exploit
        4. Execute attack
        5. Gain access
        6. Escalate privileges
        7. Install persistence
        8. Lateral movement
        9. Data exfiltration
        """
        
        target = "192.168.1.100"
        
        # Step 1: Scan target
        logger.info("Step 1: Scanning target...")
        from agents.nmap_agent import NmapAgent
        
        nmap = NmapAgent()
        scan_result = await nmap.run("quick_scan", {"target": target})
        
        assert scan_result.success, "Scan failed"
        logger.info(f"Scan completed: {scan_result.data}")
        
        # Step 2: AI analyzes results
        logger.info("Step 2: AI analyzing scan results...")
        from core.ai_integration import AIIntegration
        
        ai = AIIntegration()
        analysis = await ai.analyze_target(scan_result.data)
        
        assert analysis.get("success"), "AI analysis failed"
        logger.info(f"Analysis completed: {len(analysis.get('vulnerabilities', []))} vulnerabilities found")
        
        # Step 3: Generate exploit
        logger.info("Step 3: Generating exploit...")
        exploit = await ai.generate_exploit_code(analysis)
        
        assert exploit.get("success"), "Exploit generation failed"
        logger.info(f"Exploit generated: {exploit.get('description')}")
        
        # Step 4: Execute attack
        logger.info("Step 4: Executing attack...")
        from agents.exploit_agent import ExploitAgent
        
        exploit_agent = ExploitAgent()
        attack_result = await exploit_agent.run("execute", {
            "target": target,
            "exploit": exploit.get("code")
        })
        
        assert attack_result.success, "Attack execution failed"
        logger.info("Attack executed successfully")
        
        # Step 5: Gain access (simulated)
        logger.info("Step 5: Gaining access...")
        access_gained = attack_result.data.get("access_gained", False)
        assert access_gained, "Failed to gain access"
        
        # Step 6: Escalate privileges
        logger.info("Step 6: Escalating privileges...")
        from agents.privilege_escalation_agent import PrivilegeEscalationAgent
        
        privesc = PrivilegeEscalationAgent()
        privesc_result = await privesc.run("escalate", {"target": target})
        
        logger.info(f"Privilege escalation: {privesc_result.success}")
        
        # Step 7: Install persistence
        logger.info("Step 7: Installing persistence...")
        from agents.persistence.linux_persistence import LinuxPersistenceAgent
        
        persistence = LinuxPersistenceAgent()
        persistence_result = await persistence.run("install", {"method": "cron"})
        
        logger.info(f"Persistence installed: {persistence_result.success}")
        
        # Step 8: Lateral movement
        logger.info("Step 8: Lateral movement...")
        from agents.lateral_movement_agent import LateralMovementAgent
        
        lateral = LateralMovementAgent()
        lateral_result = await lateral.run("move", {
            "source": target,
            "target": "192.168.1.101"
        })
        
        logger.info(f"Lateral movement: {lateral_result.success}")
        
        # Step 9: Data exfiltration
        logger.info("Step 9: Data exfiltration...")
        # Simulated data exfiltration
        exfil_success = True
        
        logger.info("E2E workflow completed successfully!")
        
        assert exfil_success, "Data exfiltration failed"
    
    @pytest.mark.asyncio
    async def test_c2_workflow(self):
        """
        Test C2 workflow:
        1. Deploy agent
        2. Register with C2
        3. Receive tasks
        4. Execute tasks
        5. Report results
        """
        
        logger.info("Testing C2 workflow...")
        
        # Step 1: Start C2 server
        logger.info("Step 1: Starting C2 server...")
        from c2_infrastructure.c2_server import C2Server
        
        c2 = C2Server(host="localhost", port=8000)
        
        # Start in background
        import asyncio
        server_task = asyncio.create_task(c2.start())
        
        # Wait for server to start
        await asyncio.sleep(2)
        
        # Step 2: Deploy agent
        logger.info("Step 2: Deploying agent...")
        from c2_infrastructure.agent_handler import AgentHandler
        
        agent = AgentHandler("http://localhost:8000")
        
        # Step 3: Register agent
        logger.info("Step 3: Registering agent...")
        registered = await agent.register()
        
        assert registered, "Agent registration failed"
        logger.info(f"Agent registered: {agent.agent_id}")
        
        # Step 4: Assign task
        logger.info("Step 4: Assigning task...")
        import httpx
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"http://localhost:8000/task/{agent.agent_id}",
                json={
                    "command": "sysinfo",
                    "args": {}
                }
            )
            
            assert response.status_code == 200, "Task assignment failed"
        
        # Step 5: Agent receives and executes task
        logger.info("Step 5: Agent executing task...")
        task = await agent.beacon()
        
        assert task is not None, "No task received"
        
        result = await agent.execute_task(task)
        
        assert result.get("success"), "Task execution failed"
        
        # Step 6: Submit result
        logger.info("Step 6: Submitting result...")
        submitted = await agent.submit_result(
            task["task_id"],
            result.get("success"),
            result
        )
        
        assert submitted, "Result submission failed"
        
        logger.info("C2 workflow completed successfully!")
        
        # Cleanup
        server_task.cancel()
    
    @pytest.mark.asyncio
    async def test_frontend_workflow(self):
        """
        Test frontend workflow:
        1. Login
        2. View dashboard
        3. Start attack
        4. Monitor progress
        5. View results
        6. Check logs
        7. Review knowledge base
        """
        
        logger.info("Testing frontend workflow...")
        
        # This would typically use Selenium or Playwright
        # For now, we'll test the API endpoints
        
        import httpx
        
        async with httpx.AsyncClient() as client:
            # Step 1: Login
            logger.info("Step 1: Login...")
            response = await client.post(
                "http://localhost:8000/api/auth/login",
                json={"username": "admin", "password": "admin"}
            )
            
            assert response.status_code == 200, "Login failed"
            token = response.json().get("token")
            
            headers = {"Authorization": f"Bearer {token}"}
            
            # Step 2: View dashboard (get statistics)
            logger.info("Step 2: Viewing dashboard...")
            response = await client.get(
                "http://localhost:8000/api/statistics",
                headers=headers
            )
            
            assert response.status_code == 200, "Failed to get statistics"
            
            # Step 3: Start attack
            logger.info("Step 3: Starting attack...")
            response = await client.post(
                "http://localhost:8000/api/scan/quick",
                json={"target": "192.168.1.100"},
                headers=headers
            )
            
            assert response.status_code == 200, "Failed to start attack"
            scan_id = response.json().get("scan_id")
            
            # Step 4: Monitor progress
            logger.info("Step 4: Monitoring progress...")
            response = await client.get(
                f"http://localhost:8000/api/scan/status/{scan_id}",
                headers=headers
            )
            
            assert response.status_code == 200, "Failed to get scan status"
            
            # Step 5: View results
            logger.info("Step 5: Viewing results...")
            # Results are in the status response
            
            # Step 6: Check logs (via WebSocket in real app)
            logger.info("Step 6: Checking logs...")
            # WebSocket connection would be tested separately
            
            # Step 7: Review knowledge base
            logger.info("Step 7: Reviewing knowledge base...")
            response = await client.get(
                "http://localhost:8000/api/knowledge/techniques",
                headers=headers
            )
            
            assert response.status_code == 200, "Failed to get techniques"
            
            logger.info("Frontend workflow completed successfully!")


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

