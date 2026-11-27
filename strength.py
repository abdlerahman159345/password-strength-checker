"""Password strength checker.

Scores a password and says why: length, character types, common passwords,
keyboard patterns, repeats, dates and personal info. Also generates strong
passwords when you need one.
"""

import math
import os
import re
import secrets
import string

HERE = os.path.dirname(os.path.abspath(__file__))
COMMON_FILE = os.path.join(HERE, "common_passwords.txt")

# guessing speed used for the crack time: 10 billion guesses/second,
# about what one good GPU does against a fast hash like md5 or sha1
GUESSES_PER_SECOND = 10 * 10 ** 9

MIN_LENGTH = 8
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"

# look-alike characters, skipped when someone asks for readable passwords
CONFUSING = "0O1lI|`'\"\\;:.,{}[]()/"

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

# what people type instead of the letter
SUBS = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
        "7": "t", "8": "b", "@": "a", "$": "s", "!": "i"}

LABELS = [(80, "very strong"), (60, "strong"), (40, "fair"),
          (20, "weak"), (0, "very weak")]


def load_common_passwords():
    """Read the bundled list of the most used passwords."""
    words = set()
    try:
        with open(COMMON_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if line:
                    words.add(line)
    except FileNotFoundError:
        pass
    return words


def normalise(password):
    # p@ssw0rd and PASSWORD should both look like "password" to the checker
    lowered = password.lower()
    return "".join(SUBS.get(ch, ch) for ch in lowered)


def count_classes(password):
    kinds = []
    if any(ch.islower() for ch in password):
        kinds.append("lower")
    if any(ch.isupper() for ch in password):
        kinds.append("upper")
    if any(ch.isdigit() for ch in password):
        kinds.append("digit")
    if any(not ch.isalnum() for ch in password):
        kinds.append("symbol")
    if any(ord(ch) > 127 for ch in password):
        kinds.append("other")
    return kinds


def pool_size(password):
    # how big the alphabet is that an attacker has to search
    kinds = count_classes(password)
    size = 0
    if "lower" in kinds:
        size += 26
    if "upper" in kinds:
        size += 26
    if "digit" in kinds:
        size += 10
    if "symbol" in kinds:
        size += 33
    if "other" in kinds:
        size += 100
    return max(size, 1)


def common_hits(password, common):
    """Common passwords or words hidden inside the password."""
    lowered = normalise(password)
    found = set()
    if lowered in common:
        found.add(lowered)
    for start in range(len(lowered)):
        for end in range(start + 4, len(lowered) + 1):
            piece = lowered[start:end]
            if piece in common:
                found.add(piece)
    # "password" also contains "pass" and "word", keep the longest ones only
    return sorted([w for w in found if not any(w != o and w in o for o in found)],
                  key=len, reverse=True)


def sequences(password):
    """Runs of 3+ characters that follow each other on a keyboard."""
    lowered = password.lower()
    rows = KEYBOARD_ROWS + [string.ascii_lowercase, string.ascii_lowercase[::-1],
                            string.digits, string.digits[::-1]]
    found = []
    for i in range(len(lowered) - 2):
        piece = lowered[i:i + 3]
        if any(piece in row for row in rows):
            if found and found[-1][-1] == piece[0]:
                found[-1] += piece[-1]
            else:
                found.append(piece)
    return found


def repeats(password):
    """aaaa, abcabc and friends."""
    found = set()
    for match in re.finditer(r"(.)\1{2,}", password):
        found.add(match.group(0))
    for match in re.finditer(r"(.{2,4})\1+", password):
        found.add(match.group(0))
    return sorted(found, key=len, reverse=True)


def dates(password):
    """Years and dates. First thing someone who knows you will try."""
    found = re.findall(r"(?:19|20)\d{2}", password)
    found += re.findall(r"\b\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}\b", password)
    found += re.findall(r"(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])(?:19|20)\d{2}", password)
    return list(dict.fromkeys(found))


def personal_hits(password, personal):
    raw = password.lower()
    fixed = normalise(password)
    return [p for p in personal if p and (p in raw or p in fixed)]


def readable_time(seconds):
    if seconds < 1:
        return "instantly"
    units = [("second", 1), ("minute", 60), ("hour", 3600), ("day", 86400),
             ("month", 2629800), ("year", 31557600)]
    if seconds >= 31557600000:
        years = seconds / 31557600
        if years >= 13.8 * 10 ** 9:
            return "longer than the age of the universe"
        if years >= 10 ** 9:
            return "billions of years"
        if years >= 10 ** 6:
            return "{:,.0f} million years".format(years / 10 ** 6)
        return "{:,.0f} thousand years".format(years / 1000)
    for name, size in reversed(units):
        if seconds >= size:
            value = seconds / size
            if value >= 10:
                text = "{:,.0f}".format(value)
            else:
                text = "{:.1f}".format(value).rstrip("0").rstrip(".")
            return text + " " + name + ("" if text == "1" else "s")
    return "instantly"


def check(password, personal=()):
    """Check one password. Returns a dict with the score and the reasons."""
    personal = [p.strip().lower() for p in personal if p and p.strip()]
    common = load_common_passwords()

    length = len(password)
    kinds = count_classes(password)
    entropy = length * math.log2(pool_size(password)) if length else 0

    common_found = common_hits(password, common) if password else []
    seq_found = sequences(password)
    rep_found = repeats(password)
    date_found = dates(password)
    pers_found = personal_hits(password, personal)
    is_common = bool(password) and normalise(password) in common

    patterns = {}
    if common_found:
        patterns["common"] = common_found
    if seq_found:
        patterns["sequence"] = seq_found
    if rep_found:
        patterns["repeat"] = rep_found
    if date_found:
        patterns["date"] = date_found
    if pers_found:
        patterns["personal"] = pers_found

    issues = []
    tips = []

    if not password:
        issues.append("there is no password to check")
    elif is_common:
        issues.append("it is a common password, or a predictable version of one")
        entropy = min(entropy, 8)
    elif common_found:
        issues.append('it contains a common word or password: "%s"' % common_found[0])
        entropy -= 10 * len(common_found)

    if seq_found:
        issues.append('it contains a sequence like "%s"' % seq_found[0])
        entropy -= 6 * len(seq_found)
    if rep_found:
        issues.append('it repeats the same block: "%s"' % rep_found[0])
        entropy -= 6 * len(rep_found)
    if date_found:
        issues.append('it contains a year or a date: "%s"' % date_found[0])
        entropy -= 8 * len(date_found)
    if pers_found:
        issues.append('it contains something personal: "%s"' % pers_found[0])
        entropy -= 10 * len(pers_found)

    if length and length < MIN_LENGTH:
        issues.append("it is only %d characters long" % length)
    if length >= MIN_LENGTH and len(kinds) == 1:
        issues.append("it uses one type of character only")

    score = 0
    score += min(length, 16) * 2.5
    score += len(kinds) * 8
    if length:
        score += 18 * min(len(set(password)) / length, 1)
    if length >= 20:
        score += 8
    score -= 10 * len(common_found)
    score -= 8 * len(seq_found)
    score -= 8 * len(rep_found)
    score -= 8 * len(date_found)
    score -= 10 * len(pers_found)

    # a password in the leaked lists is broken no matter how long it looks
    if is_common:
        score = min(score, 10)
    if length < MIN_LENGTH:
        score = min(score, 35)
    score = int(round(max(0, min(100, score))))

    entropy = max(0, min(entropy, 512))
    guesses = 2 ** (entropy - 1) if entropy > 0 else 0
    crack_seconds = guesses / GUESSES_PER_SECOND

    if length < 12:
        tips.append("use at least 12 characters, 16 is better")
    if len(kinds) < 3:
        tips.append("mix upper case, lower case, digits and symbols")
    if common_found or date_found or pers_found:
        tips.append("keep names, dates and dictionary words out of it")
    if seq_found or rep_found:
        tips.append("avoid keyboard runs and repeated blocks")
    if score >= 80:
        tips.append("good password, keep it in a password manager and do not reuse it")
    elif score >= 60:
        tips.append("strong enough for most accounts, longer is still better")
    else:
        tips.append("a few random words put together is easy to remember and hard to crack")

    label = "very weak"
    for limit, name in LABELS:
        if score >= limit:
            label = name
            break

    return {
        "length": length,
        "score": score,
        "label": label,
        "entropy": round(entropy, 1),
        "crack_time": readable_time(crack_seconds),
        "issues": issues,
        "tips": tips,
        "patterns": patterns,
    }


def generate(length=20, symbols=True, readable=False):
    """Make a random password with every character type in it."""
    if length < MIN_LENGTH:
        raise ValueError("length must be at least %d" % MIN_LENGTH)

    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        pools.append(SYMBOLS)
    if readable:
        pools = ["".join(ch for ch in pool if ch not in CONFUSING) for pool in pools]

    everything = "".join(pools)
    password = [secrets.choice(pool) for pool in pools]
    password += [secrets.choice(everything) for _ in range(length - len(pools))]
    secrets.SystemRandom().shuffle(password)
    return "".join(password)
