# Password Strength Checker

A small command line tool that scores a password from 0 to 100 and explains the
score. I wrote it while studying cybersecurity because I wanted to see how
password strength is actually measured, instead of just trusting the "strong
password" bar that shows up in browsers.

It uses only the Python standard library. No dependencies, no network calls,
nothing is stored anywhere: the password never leaves the machine you run it on.

## What it checks

- length, and how many character types the password uses
- common passwords from the leaked lists (about 250 of them are bundled)
- the usual substitutions, so `p@ssw0rd` is treated as `password`
- keyboard runs like `qwerty`, `asdf` or `1234`
- repeated blocks like `aaaa` or `abcabc`
- years and dates (`1995`, `12/05/1998`)
- personal words you pass yourself with `--personal` (name, username, birth year)

## Usage

```bash
git clone https://github.com/abdlerahman159345/password-strength-checker.git
cd password-strength-checker
python3 password_checker.py
```

Run it with no arguments and it asks for the password without showing it on
screen.

Other ways to call it:

```bash
python3 password_checker.py --stdin < password.txt
python3 password_checker.py -p "Summer2024!"
python3 password_checker.py -p "ahmed1990" --personal ahmed --personal 1990
python3 password_checker.py -p "test1234" --json
python3 password_checker.py -p "123456" --fail-under 60
```

| option | what it does |
| --- | --- |
| `-p, --password` | password to check (it ends up in your shell history, the prompt is safer) |
| `--stdin` | read the password from standard input |
| `--personal WORD` | word that should not appear in the password, can be repeated |
| `--json` | print the result as JSON |
| `--fail-under SCORE` | exit with code 1 if the score is below SCORE (useful in scripts) |
| `--generate` | generate strong passwords instead of checking one |
| `--length`, `--count` | length and how many passwords to generate |
| `--no-symbols`, `--readable` | leave symbols out, or skip look-alike characters like `0`/`O` |

## Example

```
$ python3 password_checker.py
Password:
Password    ***********  (11 characters)
Length      11
Score       56 / 100  (fair)
Entropy     about 54 bits
Crack time  13 days  (at 10,000,000,000 guesses per second)
Strength    [############----------]

Issues
  - it contains a common word or password: "summer"
  - it contains a year or a date: "2024"

Tips
  - use at least 12 characters, 16 is better
  - keep names, dates and dictionary words out of it
  - a few random words put together is easy to remember and hard to crack
```

## How the score works

The password gets points for length, for the number of character types it uses
and for how many of its characters are different, then it loses points for every
pattern the checker finds. Anything that is in the common password list is
capped at 10/100, because those get cracked in seconds however long they look.

The entropy figure is `length * log2(pool size)`, where the pool is 26 for lower
case, 26 for upper case, 10 for digits and 33 for symbols. The crack time divides
the number of guesses by 10 billion guesses per second, which is roughly what a
modern GPU does against a fast hash like MD5 or SHA1. A slow hash (bcrypt,
Argon2) makes every guess thousands of times more expensive, so the real time is
usually much longer.

## Generating passwords

```bash
$ python3 password_checker.py --generate --length 20
m1ZryJ13sSt9A!=V]))f   (score 96, very strong)
```

Generated passwords use `secrets`, not `random`, and always contain lower case,
upper case, digits and symbols.

## Tests

```bash
python3 -m unittest test_strength
```

21 tests covering the checks, the generator and the command line.

## Limitations

The crack time is a rough estimate, not a promise. The model is simple compared
to tools like zxcvbn: it does not know about every leaked password, and it does
not try to guess the grammar people use to build passwords. The common password
list is short on purpose, you can drop a bigger one in
`common_passwords.txt` (one per line) and it will be used automatically.

## License

MIT, see [LICENSE](LICENSE).
