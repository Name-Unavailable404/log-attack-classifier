import re
import sys

from rules import RULES


def classify_log_line(log_line):
    matches = []

    for rule in RULES:
        pattern = rule["pattern"]

        if re.search(pattern, log_line, re.IGNORECASE):
            matches.append(rule)

    return matches


def display_results(log_line, matches):
    print("Log Line:")
    print(log_line)
    print()

    if not matches:
        print("Result: No suspicious patterns detected.")
        return

    print("Suspicious patterns detected:")
    print()

    for match in matches:
        print("Attack Type:", match["attack_type"])
        print("Confidence:", match["confidence"])
        print("Matched Rule:", match["rule_name"])
        print("Explanation:", match["explanation"])
        print()


def main():
    if len(sys.argv) < 2:
        print('Usage: python classifier.py "LOG LINE HERE"')
        return 1

    log_line = " ".join(sys.argv[1:])
    matches = classify_log_line(log_line)
    display_results(log_line, matches)

    return 0


if __name__ == "__main__":
    sys.exit(main())