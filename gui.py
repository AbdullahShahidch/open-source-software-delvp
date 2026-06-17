"""
gui.py
------
Tkinter front-end for the password strength + breach checker.

Layout:
  * Password entry (with show/hide toggle)
  * Live strength meter (colored bar, label, entropy, feedback) -- updates
    as you type, fully offline.
  * "Check for Breaches" button -- runs the HIBP k-anonymity lookup on a
    background thread (so the UI never freezes) and reports the result.

Only standard library modules are used: tkinter, threading, queue.
"""

import queue
import threading
import tkinter as tk
from tkinter import ttk

from breach import check_password_breach
from strength import check_strength

BAR_WIDTH = 360
BAR_HEIGHT = 18

# score thresholds -> color, used for both the strength bar and label
_STRENGTH_COLORS = [
    (0, "#d93025"),    # red
    (30, "#f29900"),   # orange
    (55, "#f9ab00"),   # amber
    (75, "#34a853"),   # green
    (90, "#188038"),   # dark green
]


def _color_for_score(score: int) -> str:
    color = _STRENGTH_COLORS[0][1]
    for threshold, c in _STRENGTH_COLORS:
        if score >= threshold:
            color = c
    return color


class PasswordCheckerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Strength & Breach Checker")
        self.resizable(False, False)
        self.configure(padx=24, pady=20, bg="#fafafa")

        # Queue used to safely pass results from the background network
        # thread back to the Tkinter main thread.
        self._result_queue: "queue.Queue" = queue.Queue()

        self._build_widgets()
        self._poll_queue()

    # ------------------------------------------------------------------ UI
    def _build_widgets(self):
        title = tk.Label(
            self, text="Password Checker", font=("Segoe UI", 16, "bold"),
            bg="#fafafa",
        )
        title.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))

        # --- Password entry row -------------------------------------
        tk.Label(self, text="Password:", bg="#fafafa", font=("Segoe UI", 10)).grid(
            row=1, column=0, sticky="w"
        )

        self.password_var = tk.StringVar()
        self.password_var.trace_add("write", self._on_password_change)

        self.entry = tk.Entry(
            self, textvariable=self.password_var, show="*", width=32,
            font=("Segoe UI", 11),
        )
        self.entry.grid(row=1, column=1, padx=8, pady=4, sticky="w")

        self.show_var = tk.BooleanVar(value=False)
        show_check = tk.Checkbutton(
            self, text="Show", variable=self.show_var, bg="#fafafa",
            command=self._toggle_visibility,
        )
        show_check.grid(row=1, column=2, sticky="w")

        # --- Strength meter -------------------------------------------
        tk.Label(self, text="Strength:", bg="#fafafa", font=("Segoe UI", 10)).grid(
            row=2, column=0, sticky="nw", pady=(14, 0)
        )

        self.bar_canvas = tk.Canvas(
            self, width=BAR_WIDTH, height=BAR_HEIGHT, bg="#e0e0e0",
            highlightthickness=0,
        )
        self.bar_canvas.grid(row=2, column=1, columnspan=2, sticky="w", pady=(14, 0))
        self._bar_rect = self.bar_canvas.create_rectangle(
            0, 0, 0, BAR_HEIGHT, width=0, fill="#d93025"
        )

        self.strength_label = tk.Label(
            self, text="Enter a password above", bg="#fafafa",
            font=("Segoe UI", 10, "bold"),
        )
        self.strength_label.grid(row=3, column=1, columnspan=2, sticky="w")

        self.entropy_label = tk.Label(self, text="", bg="#fafafa", font=("Segoe UI", 9), fg="#555")
        self.entropy_label.grid(row=4, column=1, columnspan=2, sticky="w")

        self.feedback_text = tk.Text(
            self, width=46, height=4, font=("Segoe UI", 9), wrap="word",
            bg="#fafafa", relief="flat", state="disabled",
        )
        self.feedback_text.grid(row=5, column=0, columnspan=3, sticky="w", pady=(4, 0))

        # --- Breach check -----------------------------------------------
        sep = ttk.Separator(self, orient="horizontal")
        sep.grid(row=6, column=0, columnspan=3, sticky="ew", pady=14)

        self.breach_button = tk.Button(
            self, text="Check for Breaches (HaveIBeenPwned)",
            command=self._start_breach_check, font=("Segoe UI", 10),
        )
        self.breach_button.grid(row=7, column=0, columnspan=3, sticky="w")

        self.breach_label = tk.Label(
            self, text="", bg="#fafafa", font=("Segoe UI", 10, "bold"), wraplength=420,
            justify="left",
        )
        self.breach_label.grid(row=8, column=0, columnspan=3, sticky="w", pady=(8, 0))

        privacy_note = tk.Label(
            self,
            text=(
                "Privacy: only the first 5 characters of your password's SHA-1 hash\n"
                "are sent to the API (k-anonymity). The full password never leaves this app."
            ),
            bg="#fafafa", font=("Segoe UI", 8), fg="#888", justify="left",
        )
        privacy_note.grid(row=9, column=0, columnspan=3, sticky="w", pady=(16, 0))

    # ------------------------------------------------------------ behavior
    def _toggle_visibility(self):
        self.entry.config(show="" if self.show_var.get() else "*")

    def _on_password_change(self, *_args):
        password = self.password_var.get()
        result = check_strength(password)
        self._render_strength(result)
        # Clear any stale breach result once the password is edited again.
        self.breach_label.config(text="", fg="black")

    def _render_strength(self, result: dict):
        score = result["score"]
        color = _color_for_score(score)
        fill_width = int((score / 100) * BAR_WIDTH)
        self.bar_canvas.coords(self._bar_rect, 0, 0, fill_width, BAR_HEIGHT)
        self.bar_canvas.itemconfig(self._bar_rect, fill=color)

        self.strength_label.config(text=f"{result['label']}  ({score}/100)", fg=color)
        self.entropy_label.config(text=f"Estimated entropy: {result['entropy']} bits")

        self.feedback_text.config(state="normal")
        self.feedback_text.delete("1.0", "end")
        self.feedback_text.insert("1.0", "\n".join(f"- {f}" for f in result["feedback"]))
        self.feedback_text.config(state="disabled")

    def _start_breach_check(self):
        password = self.password_var.get()
        if not password:
            self.breach_label.config(text="Type a password first.", fg="#d93025")
            return

        self.breach_button.config(state="disabled", text="Checking...")
        self.breach_label.config(text="Contacting Have I Been Pwned...", fg="#555")

        thread = threading.Thread(
            target=self._run_breach_check_in_background, args=(password,), daemon=True
        )
        thread.start()

    def _run_breach_check_in_background(self, password: str):
        result = check_password_breach(password)
        self._result_queue.put(result)

    def _poll_queue(self):
        """Runs on the main thread; checks for results from background
        threads roughly 10 times a second and updates the UI safely."""
        try:
            result = self._result_queue.get_nowait()
        except queue.Empty:
            pass
        else:
            self._render_breach_result(result)
        self.after(100, self._poll_queue)

    def _render_breach_result(self, result: dict):
        self.breach_button.config(state="normal", text="Check for Breaches (HaveIBeenPwned)")

        if result["error"]:
            self.breach_label.config(text=f"Could not check: {result['error']}", fg="#d93025")
            return

        if result["breached"]:
            count = result["count"]
            self.breach_label.config(
                text=(
                    f"This password was found in {count:,} known breach(es).\n"
                    "Stop using it and change it anywhere it's reused."
                ),
                fg="#d93025",
            )
        else:
            self.breach_label.config(
                text="Good news: this password was not found in any known breach.",
                fg="#188038",
            )


def run():
    app = PasswordCheckerApp()
    app.mainloop()
