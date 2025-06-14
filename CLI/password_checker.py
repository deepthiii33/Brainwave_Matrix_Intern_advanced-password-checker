import re
import os
import hashlib
import requests
from colorama import Fore, Style, init

init(autoreset=True)

def load_rockyou_passwords(path="/usr/share/wordlists/rockyou.txt"):
    if not os.path.exists(path):
        print(f"[!] {path} not found!")
        return set()
    with open(path, "r", encoding="latin-1", errors="ignore") as f:
        return set(line.strip() for line in f)

def normalize_leet(password):
    substitutions = {
        '@': 'a', '0': 'o', '1': 'l', '$': 's', '3': 'e', '4': 'a', '5': 's', '7': 't', '!': 'i'
    }
    normalized = password.lower()
    for k, v in substitutions.items():
        normalized = normalized.replace(k, v)
    return normalized

def detect_common_words(password):
    common_words = ['password', 'admin', 'welcome', 'login', 'user', 'letmein', 'deepthi', 'test', 'root', 'toor']
    normalized = normalize_leet(password)
    for word in common_words:
        if word in normalized:
            return word
    return None

def detect_keyboard_patterns(password):
    keyboard_patterns = ["qwerty", "asdfgh", "zxcvbn", "12345", "09876"]
    for pattern in keyboard_patterns:
        if pattern in password.lower():
            return pattern
    return None

def has_common_pattern(password):
    patterns = {
        "123456": "Consecutive numbers → '123456'",
        "abcdef": "Consecutive letters → 'abcdef'",
        "qwerty": "Keyboard pattern → 'qwerty'",
        "asdfgh": "Keyboard pattern → 'asdfgh'",
        "password": "Common word → 'password'",
        r"(.)\1{2,}": "Repeated character → '{}'",
        r"\d{4,}": "4+ digit sequence → '{}'",
        r"(?:19|20)\d{2}": "Year-like number → '{}'",
    }
    for pattern, desc in patterns.items():
        match = re.search(pattern, password, re.IGNORECASE)
        if match:
            return desc.format(match.group(0))
    return None

def get_strength_level(password):
    length = len(password)
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_digit = bool(re.search(r'[0-9]', password))
    has_special = bool(re.search(r'[^A-Za-z0-9]', password))

    score = sum([has_upper, has_lower, has_digit, has_special])

    if length < 8 or score < 2:
        return "Very Weak 🔴"
    elif length < 10 or score < 3:
        return "Weak 🟠"
    elif length >= 12 and score == 4:
        return "Strong 🟢"
    else:
        return "Medium 🟡"

def get_password_feedback(password):
    suggestions = []
    if len(password) < 12:
        suggestions.append("Use at least 12 characters")
    if not re.search(r'[A-Z]', password):
        suggestions.append("Add an uppercase letter")
    if not re.search(r'[a-z]', password):
        suggestions.append("Add a lowercase letter")
    if not re.search(r'[0-9]', password):
        suggestions.append("Add a number")
    if not re.search(r'[^A-Za-z0-9]', password):
        suggestions.append("Add a special character (!@#$...)")
    repeated = re.search(r"(.)\1{2,}", password)
    if repeated:
        suggestions.append(f"Avoid repeating the same character → '{repeated.group(0)}'")
    return suggestions

def check_hibp(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
    except requests.RequestException:
        return -1
    hashes = (line.split(':') for line in response.text.splitlines())
    for h, _ in hashes:
        if h == suffix:
            return True
    return False

def main():
    print(Fore.CYAN + Style.BRIGHT + "\n🔐 Welcome to the Password Strength Checker\n")

    password = input("Enter your password: ")

    breached = False
    print("\n🔄 Checking against online breached databases...")
    hibp_result = check_hibp(password)
    if hibp_result == -1:
        print(Fore.YELLOW + "⚠️  Could not connect to online breach database (HaveIBeenPwned)")
    elif hibp_result:
        print(Fore.RED + f"❌ Found in online breach database")
        breached = True
    else:
        print(Fore.GREEN + "✅ Not found in online breach database")

    print("\n🔄 Checking against known breached passwords (rockyou.txt)...")
    rockyou = load_rockyou_passwords()
    if password in rockyou:
        print(Fore.RED + "❌ This password has been found in local breached password list")
        breached = True
    else:
        print(Fore.GREEN + "✅ Password not found in local breached list")

    print("\n🔍 Analysis Results:")
    strength = get_strength_level(password)
    print(f"Strength: {strength}")

    common_word = detect_common_words(password)
    if common_word:
        print(Fore.RED + f"⚠️  Warning: Your password is similar to the common word → '{common_word}'")

    keyboard_pattern = detect_keyboard_patterns(password)
    if keyboard_pattern:
        print(Fore.RED + f"⚠️  Warning: Your password contains the weak keyboard pattern → '{keyboard_pattern}'")

    pattern_warning = has_common_pattern(password)
    if pattern_warning:
        print(Fore.RED + f"⚠️  Warning: {pattern_warning}")

    suggestions = get_password_feedback(password)
    if suggestions:
        print("\n💡 Suggestions to improve your password:")
        for suggestion in suggestions:
            print(f" - {suggestion}")
    else:
        print(Fore.GREEN + "\n✅ Your password is well-structured!")

if __name__ == "__main__":
    main()
