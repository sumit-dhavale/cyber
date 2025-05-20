import tkinter as tk
from tkinter import messagebox
import re

def check_password_strength():
    password = entry.get()
    
    # Criteria checks
    length = len(password) >= 8
    lowercase = re.search(r'[a-z]', password) is not None
    uppercase = re.search(r'[A-Z]', password) is not None
    digit = re.search(r'\d', password) is not None
    special = re.search(r'[!@#$%^&*(),.?":{}|<>]', password) is not None

    score = sum([length, lowercase, uppercase, digit, special])

    # Strength rating
    if score == 5:
        strength = "Very Strong"
        color = "green"
    elif score == 4:
        strength = "Strong"
        color = "blue"
    elif score == 3:
        strength = "Moderate"
        color = "orange"
    elif score == 2:
        strength = "Weak"
        color = "orangered"
    else:
        strength = "Very Weak"
        color = "red"

    result_label.config(text=f"Strength: {strength}", fg=color)

    # Feedback
    feedback = []
    if not length:
        feedback.append("- Use at least 8 characters.")
    if not lowercase:
        feedback.append("- Add lowercase letters.")
    if not uppercase:
        feedback.append("- Add uppercase letters.")
    if not digit:
        feedback.append("- Include numbers.")
    if not special:
        feedback.append("- Use special characters (!@#...).")

    feedback_text.config(state='normal')
    feedback_text.delete('1.0', tk.END)
    feedback_text.insert(tk.END, "\n".join(feedback))
    feedback_text.config(state='disabled')


# GUI Setup
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("400x300")
root.resizable(False, False)

tk.Label(root, text="Enter your password:", font=("Arial", 12)).pack(pady=10)
entry = tk.Entry(root, width=30, show="*", font=("Arial", 12))
entry.pack()

tk.Button(root, text="Check Strength", command=check_password_strength).pack(pady=10)

result_label = tk.Label(root, text="", font=("Arial", 14, "bold"))
result_label.pack()

tk.Label(root, text="Suggestions:", font=("Arial", 10)).pack()
feedback_text = tk.Text(root, width=45, height=5, state='disabled', wrap='word', bg="#f0f0f0")
feedback_text.pack(pady=5)

root.mainloop()
