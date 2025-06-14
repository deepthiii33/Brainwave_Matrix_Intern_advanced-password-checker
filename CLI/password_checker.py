import math
import re
import os
from colorama import Fore, Style, init

init(autoreset=True)

def load_rockyou_passwords(path="/usr/share/wordlists/rockyou.txt"):
    if not os.path.exists(path):
        print(f"[!] {path} not found!")
        return set()
    with open(path, "r", encoding="latin-1", errors="ignore") as f:
        return set(line.strip() for line in f)

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
    if re.search(r"(.)\1{2,}", password):
        suggestions.append("Avoid repeating the same character multiple times")
    return suggestions

def has_common_pattern(password):
    patterns = [
        "123456", "abcdef", "qwerty", "asdfgh", "password", "iloveyou",
        r"(.)\1{2,}",  # repeated chars like aaaaa
        r"\d{4,}",     # 4+ digit sequences
        r"(?:19|20)\d{2}",  # years like 1999, 2023
    ]
    for pattern in patterns:
        if re.search(pattern, password, re.IGNORECASE):
            return True
    return False

def detect_common_words(password):
    # Small sample of common words/names — you can expand this list
    common_words = ['password', 'admin', 'welcome', 'login', 'user', 'letmein', 'deepthi', 'test', 'root']
    for word in common_words:
        if word in password.lower():
            return word
    return None

def detect_keyboard_patterns(password):
    keyboard_patterns = ["qwerty", "asdfgh", "zxcvbn", "12345", "09876"]
    for pattern in keyboard_patterns:
        if pattern in password.lower():
            return pattern
    return None

def calculate_entropy(password):
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'[0-9]', password): charset += 10
    if re.search(r'[^A-Za-z0-9]', password): charset += 32
    if charset == 0: return 0
    return len(password) * math.log2(charset)

def estimate_crack_times(entropy):
    guesses_per_sec = {
        "Online attack (1k guesses/sec)": 1e3,
        "Offline fast attack (1B guesses/sec)": 1e9,
        "Supercomputer attack (100B guesses/sec)": 1e11,
    }
    results = {}
    total_guesses = 2 ** entropy
    for attack_type, rate in guesses_per_sec.items():
        seconds = total_guesses / rate
        if seconds < 1:
            results[attack_type] = "less than 1 second"
        elif seconds < 60:
            results[attack_type] = f"{int(seconds)} seconds"
        elif seconds < 3600:
            results[attack_type] = f"{int(seconds / 60)} minutes"
        elif seconds < 86400:
            results[attack_type] = f"{int(seconds / 3600)} hours"
        elif seconds < 31536000:
            results[attack_type] = f"{int(seconds / 86400)} days"
        else:
            results[attack_type] = f"{int(seconds / 31536000)} years"
    return results

def get_strength_level(entropy):
    if entropy < 28: return "Very Weak 🔴"
    elif entropy < 36: return "Weak 🟠"
    elif entropy < 60: return "Medium 🟡"
    else: return "Strong 🟢"

def main():
    print(Fore.CYAN + Style.BRIGHT +" \n🔐 Welcome to the Advanced Password Strength Checker\n")

    password = input("Enter your password: ")

    print("\n🔄 Checking against known breached passwords...")
    rockyou = load_rockyou_passwords()

    print("\n🔍 Analysis Results:")
    if password in rockyou:
        print(Fore.RED + "❌ This password has been found in previous data breaches")
    else:
        print(Fore.GREEN + "✅ Password not found in breached list")

    entropy = calculate_entropy(password)
    strength = get_strength_level(entropy)

    print(f"\nEntropy: {entropy:.2f} bits")
    print(f"Strength: {strength}")

    crack_times = estimate_crack_times(entropy)
    print("\n🔑 Estimated Crack Times:")
    for attack_type, time in crack_times.items():
        print(f" - {attack_type}: {time}")

    # New: Common word detection
    common_word = detect_common_words(password)
    if common_word:
        print(Fore.RED + "⚠️  Warning: Your password contains a common name or word, making it easier to guess.")

    # New: Keyboard pattern detection
    keyboard_pattern = detect_keyboard_patterns(password)
    if keyboard_pattern:
        print(Fore.RED + f"⚠️  Warning: Your password contains the weak keyboard pattern '{keyboard_pattern}'")

    if has_common_pattern(password):
        print(Fore.RED + "⚠️  Warning: Avoid common patterns like '123456', 'qwerty', or repeated characters.")

    suggestions = get_password_feedback(password)
    if suggestions:
        print("\n💡 Suggestions to improve your password:")
        for suggestion in suggestions:
            print(f" - {suggestion}")
    else:
        print(Fore.GREEN + "\n✅ Your password is well-structured!")

if __name__ == "__main__":
    main()

