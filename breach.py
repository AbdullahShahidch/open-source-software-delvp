"""
breach.py
---------   this is new branch
Checks whether a password has appeared in known data breaches, using the
"Pwned Passwords" k-Anonymity API from Have I Been Pwned:

    https://haveibeenpwned.com/API/v3#PwnedPasswords

Privacy note: the real password is NEVER sent over the network. We hash it
locally with SHA-1, then send only the first 5 characters of that hash
(the "prefix") to the API. The API responds with every hash suffix that
shares that prefix, and we check locally whether our full hash is among
them. The server never sees enough of the hash to know which password it
is for (k-anonymity).

Only the Python standard library is used (urllib, hashlib, json) -- no
extra packages need to be installed.
"""

import hashlib
import json
import urllib.error
import urllib.request

API_URL = "https://api.pwnedpasswords.com/range/{}"
USER_AGENT = "Tkinter-Password-Checker/1.0 (educational project)"


def check_password_breach(password: str, timeout: int = 8) -> dict:
    """Query the HIBP Pwned Passwords API for this password.

    Returns a dict with:
        breached -- True / False / None (None means the check failed,
                    e.g. no internet connection)
        count    -- how many times this exact password has been seen in
                    breaches (0 if not found or unknown)
        error    -- a human readable error string, or None if no error
    """
    if not password:
        return {"breached": None, "count": 0, "error": "No password provided."}

    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    request = urllib.request.Request(
        API_URL.format(prefix),
        headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return {"breached": None, "count": 0, "error": f"API error: HTTP {e.code}"}
    except urllib.error.URLError as e:
        return {
            "breached": None,
            "count": 0,
            "error": f"Could not reach the breach database (no internet?): {e.reason}",
        }
    except Exception as e:  # pragma: no cover - defensive catch-all
        return {"breached": None, "count": 0, "error": f"Unexpected error: {e}"}

    for line in body.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        hash_suffix, count_str = line.split(":", 1)
        if hash_suffix.strip().upper() == suffix:
            try:
                count = int(count_str.strip())
            except ValueError:
                count = 0
            return {"breached": True, "count": count, "error": None}

    return {"breached": False, "count": 0, "error": None}


if __name__ == "__main__":
    # Quick manual test from the command line:
    #   python breach.py "somepassword"
    import sys

    pw = sys.argv[1] if len(sys.argv) > 1 else "password"
    result = check_password_breach(pw)
    print(json.dumps(result, indent=2))
