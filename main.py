"""
main.py
-------
Entry point. Run with:

    python main.py

Requires no third-party packages -- only the Python standard library
(tkinter, hashlib, urllib, threading, queue). Internet access is only
needed when you click "Check for Breaches"; password strength checking
works fully offline.
"""

from gui import run

if __name__ == "__main__":
    run()
