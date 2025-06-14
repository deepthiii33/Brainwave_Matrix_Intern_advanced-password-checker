import tkinter as tk
from tkinter import messagebox, filedialog
import math
import re
import hashlib
import requests

def calculate_entropy(password):
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'[0-9]', password): charset += 10
    if re.search(r'[^A-Za-z0-9]', password): charset += 32
    if charset == 0: return 0
    return len(password) * math.log2(charset)

def get_strength_level(entropy):
    if entropy < 28: return "Very Weak"
    elif entropy < 36: return "Weak"
    elif entropy < 60: return "Medium"
    else: return "Strong"

def estimate_crack_times(entropy):
    guesses_per_sec = {
        "Online attack (1k/sec)": 1e3,
        "Offline fast attack (1B/sec)": 1e9,
        "Supercomputer attack (100B/sec)": 1e11,
    }
    results = {}
    total_guesses = 2 ** entropy
    for attack_type, rate in guesses_per_sec.items():
        seconds = total_guesses / rate
        if seconds < 1:
            results[attack_type] = "<1 sec"
        elif seconds < 60:
            results[attack_type] = f"{int(seconds)} sec"
        elif seconds < 3600:
            results[attack_type] = f"{int(seconds / 60)} min"
        elif seconds < 86400:
            results[attack_type] = f"{int(seconds / 3600)} hrs"
        elif seconds < 31536000:
            results[attack_type] = f"{int(seconds / 86400)} days"
        else:
            results[attack_type] = f"{int(seconds / 31536000)} yrs"
    return results

def check_hibp_api(password):
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        response = requests.get(url, timeout=5)
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)
        return 0
    except:
        return -1

def get_password_feedback(password):
    suggestions = []
    if len(password) < 12:
        suggestions.append("Use at least 12 characters")
    if not re.search(r'[A-Z]', password):
        suggestions.append("Add an uppercase letter")
    if not re.search(r'[0-9]', password):
        suggestions.append("Add a number")
    if not re.search(r'[^A-Za-z0-9]', password):
        suggestions.append("Add a special character (!@#$...)")
    return suggestions

def analyze_password(password):
    hibp_result = check_hibp_api(password)
    entropy = calculate_entropy(password)
    strength = get_strength_level(entropy)
    cracks = estimate_crack_times(entropy)
    feedback = get_password_feedback(password)

    result = ""

    if hibp_result > 0:
        result += "❌ Found in common breached password lists\n\n"
    elif hibp_result == -1:
        result += "⚠️ Could not check breach status\n\n"
    else:
        result += "✅ Password not found in breached list\n\n"

    result += f"Strength: {strength}\n"
    result += f"Entropy: {entropy:.2f} bits\n\n"

    for atk, time in cracks.items():
        result += f"{atk}: {time}\n"

    if feedback:
        result += "\nSuggestions to improve:\n"
        for f in feedback:
            result += f"- {f}\n"

    return result

def analyze_password_gui():
    pwd = password_entry.get()
    if not pwd:
        messagebox.showwarning("Input Required", "Please enter a password.")
        return

    result_text.config(state='normal')
    result_text.delete(1.0, tk.END)
    result = analyze_password(pwd)
    result_text.insert(tk.END, result)
    result_text.config(state='disabled')

def update_strength_label(event=None):
    pwd = password_entry.get()
    entropy = calculate_entropy(pwd)
    strength = get_strength_level(entropy)
    if strength == "Very Weak":
        strength_label.config(text=f"Strength: {strength}", fg="red")
    elif strength == "Weak":
        strength_label.config(text=f"Strength: {strength}", fg="orange")
    elif strength == "Medium":
        strength_label.config(text=f"Strength: {strength}", fg="blue")
    else:
        strength_label.config(text=f"Strength: {strength}", fg="green")

def batch_check():
    filepath = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if not filepath:
        return
    result_text.config(state='normal')
    result_text.delete(1.0, tk.END)

    try:
        with open(filepath, 'r') as f:
            passwords = f.read().splitlines()
        for pwd in passwords:
            result_text.insert(tk.END, f"🔑 {pwd}\n")
            result = analyze_password(pwd)
            result_text.insert(tk.END, result + "\n" + "-" * 50 + "\n")
    except Exception as e:
        result_text.insert(tk.END, f"Error reading file: {e}\n")

    result_text.config(state='disabled')

# GUI setup
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("550x600")
root.resizable(False, False)

header = tk.Label(root, text="🔐 Advanced Password Strength Checker", font=("Arial", 16, "bold"), fg="#1e90ff")
header.pack(pady=10)

password_entry = tk.Entry(root, width=40, font=("Arial", 12))
password_entry.pack(pady=5)
password_entry.bind('<KeyRelease>', update_strength_label)

strength_label = tk.Label(root, text="Strength: ", font=("Arial", 12, "bold"))
strength_label.pack()

check_btn = tk.Button(root, text="Check Password", command=analyze_password_gui, font=("Arial", 12), bg="#1e90ff", fg="white")
check_btn.pack(pady=5)

batch_btn = tk.Button(root, text="Batch Check (Upload File)", command=batch_check, font=("Arial", 12), bg="#32a852", fg="white")
batch_btn.pack(pady=5)

result_text = tk.Text(root, width=65, height=22, font=("Courier", 10))
result_text.pack(pady=10)
result_text.config(state='disabled')

root.mainloop()

