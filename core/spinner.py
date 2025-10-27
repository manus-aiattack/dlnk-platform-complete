import asyncio
from rich.spinner import Spinner
from rich.console import Console

class SpinnerManager:
    def __init__(self, console: Console):
        self.console = console
        self._spinner_task = None
        self._spinner_running = False

    async def _run_spinner(self, text: str):
        """The async task that runs the spinner."""
        spinner = Spinner("dots", text=text)
        while self._spinner_running:
            self.console.print(spinner, end="\r")
            await asyncio.sleep(0.1)

    def start(self, text: str = "Processing..."):
        """Starts the spinner in a background task."""
        if not self._spinner_running:
            self._spinner_running = True
            self._spinner_task = asyncio.create_task(self._run_spinner(text))

    def stop(self):
        """Stops the spinner."""
        if self._spinner_running:
            self._spinner_running = False
            if self._spinner_task:
                self._spinner_task.cancel()
                # Clear the line where the spinner was
                self.console.print(" " * (len(self._spinner_task.get_name()) + 20), end="\r")
