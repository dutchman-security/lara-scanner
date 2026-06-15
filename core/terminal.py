"""
Thread-safe terminal output manager.
Keeps a persistent progress bar line that never hides permanent output.
"""

import sys
import threading

from colorama import Fore, Style

# ── Styling constants (re-exported for convenience) ──
OK     = f"{Fore.GREEN}[✓]{Style.RESET_ALL}"
INFO   = f"{Fore.CYAN}[*]{Style.RESET_ALL}"
WARN   = f"{Fore.YELLOW}[!]{Style.RESET_ALL}"
ERR    = f"{Fore.RED}[✗]{Style.RESET_ALL}"
FOUND  = f"{Fore.GREEN}[✔]{Style.RESET_ALL}"
BRIGHT = Fore.LIGHTWHITE_EX


class Terminal:
    """Manages terminal output so the progress bar never hides findings."""

    def __init__(self):
        self.lock = threading.Lock()
        self.progress_line = ""

    def _clear_line(self):
        sys.stdout.write("\r" + " " * 100 + "\r")
        sys.stdout.flush()

    def progress(self, text: str):
        """Update the one-line progress bar at the bottom of the screen."""
        with self.lock:
            self._clear_line()
            self.progress_line = text
            sys.stdout.write(text)
            sys.stdout.flush()

    def print(self, text: str = ""):
        """Print a permanent line without corrupting the progress bar."""
        with self.lock:
            self._clear_line()
            sys.stdout.write(text + "\n")
            if self.progress_line:
                sys.stdout.write(self.progress_line)
            sys.stdout.flush()

    def done(self):
        """Remove the progress bar for the final time."""
        with self.lock:
            self._clear_line()
            self.progress_line = ""
            sys.stdout.flush()


# Singleton shared across modules
term = Terminal()
