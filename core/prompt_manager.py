import os
from pathlib import Path
from core.logger import log


class PromptManager:
    def __init__(self, prompt_dir: str = "prompts"):
        self.prompt_dir = Path(prompt_dir)
        if not self.prompt_dir.is_dir():
            log.critical(f"Prompt directory '{self.prompt_dir}' not found!")
            raise FileNotFoundError(
                f"Prompt directory '{self.prompt_dir}' not found!")

        self.prompts = {}
        self.load_prompts()

    def load_prompts(self):
        """Loads all .txt files from the prompt directory into memory."""
        for prompt_file in self.prompt_dir.glob("*.txt"):
            agent_name = prompt_file.stem.replace("_prompt", "")
            try:
                with open(prompt_file, 'r') as f:
                    self.prompts[agent_name] = f.read().strip()
                log.info(
                    f"Loaded prompt for '{agent_name}' from {prompt_file.name}")
            except Exception as e:
                log.error(f"Failed to load prompt {prompt_file.name}: {e}")

    def get_prompt(self, agent_name: str, **kwargs) -> str | None:
        """Gets the prompt for a given agent and formats it with provided context."""
        prompt_template = self.prompts.get(agent_name)
        if not prompt_template:
            log.error(f"Prompt for agent '{agent_name}' not found.")
            return None

        try:
            return prompt_template.format(**kwargs)
        except KeyError as e:
            log.error(f"Missing key {e} for formatting prompt '{agent_name}'")
            return None  # Or return the raw template

    def apply_modification(self, target_agent: str, new_prompt_segment: str, instruction: str):
        """
        Applies a modification to a specific agent's prompt.
        For simplicity, this implementation appends the new segment.
        A more complex implementation could use placeholders or markers.
        """
        prompt_template = self.prompts.get(target_agent)
        if not prompt_template:
            log.error(
                f"Cannot apply modification: Prompt for agent '{target_agent}' not found.")
            return

        log.warning(
            f"Applying dynamic prompt modification to '{target_agent}' based on instruction: '{instruction}'")
        # Append the new guidance to the end of the prompt, before the final output instruction.
        # This is a simple but effective way to add new context or constraints.
        self.prompts[
            target_agent] += f"\n\n**Dynamic Guidance from MetaCognitionAgent:**\n- {new_prompt_segment}\n"
