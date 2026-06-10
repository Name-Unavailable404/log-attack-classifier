import re
import sys
from pathlib import Path

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


def scan_file(file_path):
    path = Path(file_path)

    if not path.exists():
        print(f"File not found: {file_path}")
        return 1

    if not path.is_file():
        print(f"Path is not a file: {file_path}")
        return 1

    with path.open("r", encoding="utf-8") as file:
        lines = file.readlines()

    suspicious_count = 0

    for line_number, line in enumerate(lines, start=1):
        log_line = line.strip()

        if not log_line:
            continue

        matches = classify_log_line(log_line)

        if matches:
            suspicious_count += 1
            print("=" * 60)
            print(f"Line {line_number}")
            display_results(log_line, matches)

    print("=" * 60)
    print("Scan Summary")
    print(f"Total lines scanned: {len(lines)}")
    print(f"Suspicious lines found: {suspicious_count}")

    return 0


def main():
    if len(sys.argv) < 2:
        print('Usage:')
        print('  python classifier.py "LOG LINE HERE"')
        print('  python classifier.py samples/sample_logs.txt')
        return 1

    user_input = " ".join(sys.argv[1:])
    possible_file = Path(user_input)

    if possible_file.exists():
        return scan_file(user_input)

    matches = classify_log_line(user_input)
    display_results(user_input, matches)

    return 0


if __name__ == "__main__":
    sys.exit(main())