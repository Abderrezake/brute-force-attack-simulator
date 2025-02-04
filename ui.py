import tkinter as tk
from tkinter import messagebox
from hashing import hash_password
from brute_force import brute_force_attack

def start_attack():
    hashed_password = hash_password(password_entry.get(), algorithm_entry.get())
    max_length = int(length_entry.get())
    cracked_password, duration, attempts, attempts_per_second = brute_force_attack(
        hashed_password, algorithm_entry.get(), max_length
    )
    if cracked_password:
        messagebox.showinfo(
            "Success",
            f"Password: {cracked_password}\nTime: {duration:.2f} seconds\nAttempts: {attempts}\nAttempts/sec: {attempts_per_second:.2f}"
        )
    else:
        messagebox.showinfo("Failure", "Failed to crack the password.")

# Tkinter UI setup
root = tk.Tk()
root.title("Brute Force Simulator")

tk.Label(root, text="Algorithm:").grid(row=0, column=0)
algorithm_entry = tk.Entry(root)
algorithm_entry.insert(0, "sha256")
algorithm_entry.grid(row=0, column=1)

tk.Label(root, text="Password:").grid(row=1, column=0)
password_entry = tk.Entry(root)
password_entry.grid(row=1, column=1)

tk.Label(root, text="Max Length:").grid(row=2, column=0)
length_entry = tk.Entry(root)
length_entry.insert(0, "4")
length_entry.grid(row=2, column=1)

tk.Button(root, text="Start Attack", command=start_attack).grid(row=3, column=0, columnspan=2)

root.mainloop()
