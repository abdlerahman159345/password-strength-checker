#!/usr/bin/env python3
"""Command line front end for the password strength checker.

Run it with no arguments and it asks for the password without showing it:

    python3 password_checker.py

Other ways to use it:

    python3 password_checker.py --stdin < pass.txt
    python3 password_checker.py -p "Summer2024!"
    python3 password_checker.py -p "ahmed1990" --personal ahmed --personal 1990
    python3 password_checker.py --generate --length 24
    python3 password_checker.py -p "test1234" --json
"""

import argparse
import getpass
import json
import sys

import strength

BAR_WIDTH = 22


def bar(score):
    filled = int(round(BAR_WIDTH * score / 100.0))
    return "[" + "#" * filled + "-" * (BAR_WIDTH - filled) + "]"


def show(result, show_password=False):
    print()
    if show_password:
        print("Password    " + "*" * result["length"] + "  (%d characters)" % result["length"])
    print("Length      %d" % result["length"])
    print("Score       %d / 100  (%s)" % (result["score"], result["label"]))
    print("Entropy     about %d bits" % round(result["entropy"]))
    print("Crack time  %s  (at %s guesses per second)"
          % (result["crack_time"], "{:,}".format(strength.GUESSES_PER_SECOND)))
    print("Strength    %s" % bar(result["score"]))

    if result["issues"]:
        print()
        print("Issues")
        for issue in result["issues"]:
            print("  - " + issue)

    if result["tips"]:
        print()
        print("Tips")
        for tip in result["tips"]:
            print("  - " + tip)
    print()


def get_password(args):
    if args.stdin:
        return sys.stdin.readline().rstrip("\n")
    if args.password is not None:
        return args.password
    return getpass.getpass("Password: ")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check how strong a password is, or generate a strong one.")
    parser.add_argument("-p", "--password",
                        help="password to check (it stays in your shell history, "
                             "so the prompt or --stdin is safer)")
    parser.add_argument("--stdin", action="store_true",
                        help="read the password from standard input")
    parser.add_argument("--personal", action="append", default=[], metavar="WORD",
                        help="name, username, birth year... that should not be in the "
                             "password (can be repeated)")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    parser.add_argument("--fail-under", type=int, metavar="SCORE",
                        help="exit with code 1 when the score is lower than this")
    parser.add_argument("--generate", action="store_true",
                        help="generate a strong password instead of checking one")
    parser.add_argument("--length", type=int, default=20,
                        help="length of generated passwords (default 20)")
    parser.add_argument("--count", type=int, default=1,
                        help="how many passwords to generate (default 1)")
    parser.add_argument("--no-symbols", action="store_true",
                        help="generated passwords without symbols")
    parser.add_argument("--readable", action="store_true",
                        help="generated passwords without look-alike characters (0/O, 1/l/I)")
    args = parser.parse_args(argv)

    if args.generate:
        try:
            for _ in range(max(1, args.count)):
                password = strength.generate(args.length,
                                             symbols=not args.no_symbols,
                                             readable=args.readable)
                if args.json:
                    print(json.dumps(strength.check(password), indent=2))
                else:
                    result = strength.check(password)
                    print("%s   (score %d, %s)" % (password, result["score"], result["label"]))
        except ValueError as error:
            parser.error(str(error))
        return 0

    password = get_password(args)
    result = strength.check(password, args.personal)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        show(result, show_password=True)

    if args.fail_under is not None and result["score"] < args.fail_under:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
