# Password Strength & Breach Checker (Tkinter)

A small, dependency-free desktop app, built only with the Python
standard library (`tkinter`, `hashlib`, `urllib`, `threading`, `queue`),
that helps you evaluate a password in two ways:

1. **Strength check** (fully offline) — scores the password 0-100 based
   on length, character variety, repeated characters, and whether it's
   one of the most common leaked passwords, and estimates its entropy
   in bits.
2. **Breach check** (needs internet) — looks the password up against the
   [Have I Been Pwned "Pwned Passwords"](https://haveibeenpwned.com/Passwords)
   database using the official k-anonymity API, so you find out if it's
   ever shown up in a known data breach.

## Privacy

The breach check never sends your actual password anywhere. It's hashed
locally with SHA-1, and only the **first 5 characters** of that hash are
sent to the API. The server returns every breached hash sharing that
prefix, and the match is found locally. This means the API itself can't
tell which password you checked.

## Requirements

- Python 3.8+
- Tkinter (ships with most standard Python installs; on Linux you may
  need to install it separately, e.g. `sudo apt install python3-tk`)
- An internet connection — only needed for the breach check button;
  strength checking works fully offline.

No `pip install` is required — everything else is standard library.

## Running it

```bash
python main.py
```

## Project structure

```
password_checker/
├── main.py      # entry point, starts the GUI
├── gui.py       # Tkinter UI: entry field, strength meter, breach button
├── strength.py  # offline password strength / entropy scoring
├── breach.py    # HaveIBeenPwned k-anonymity breach lookup
└── README.md
```

## Notes & possible extensions

- The strength rules are intentionally simple/transparent rather than a
  full implementation of something like zxcvbn — feel free to tune the
  scoring in `strength.py`.
- `breach.py` can also be run standalone for a quick CLI check:
  ```bash
  python breach.py "somepassword"
  ```
- Ideas for extending it further: a "generate strong password" button,
  a password history/strength log, or bundling a larger offline common-
  password wordlist for when there's no internet connection.
