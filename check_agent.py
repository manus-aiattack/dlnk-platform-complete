import sys
import inspect
from agents.ssrf_agent_weaponized import SSRFAgentWeaponized
from agents.bola_agent_weaponized import BOLAAgentWeaponized

for name, cls in [('SSRFAgentWeaponized', SSRFAgentWeaponized), ('BOLAAgentWeaponized', BOLAAgentWeaponized)]:
    print(f"\nChecking {name}:")
    print(f"  Class: {cls}")
    print(f"  Has 'run' method: {hasattr(cls, 'run')}")
    print(f"  Ends with 'Agent': {name.endswith('Agent')}")
    print(f"  Is BaseAgent: {name == 'BaseAgent'}")
    print(f"  Is class: {inspect.isclass(cls)}")

