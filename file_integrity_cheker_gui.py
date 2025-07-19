import hashlib
import os
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, scrolledtext


# ----- Core Functions -----

def get_file_list(path):
    if os.path.isfile(path):
        return [path]
    elif os.path.isdir(path):
        file_list = []
        for root, dirs, files in os.walk(path):
            for f in files:
                file_list.append(os.path.join(root, f))
        return file_list
    else:
        return []


def compute_hash(filepath):
    sha512 = hashlib.sha512()
    try:
        with open(filepath, "rb") as f:
            while True:
                data = f.read(4096)
                if not data:
                    break
                sha512.update(data)
        return sha512.hexdigest()
    except Exception:
        return None


def create_baseline(path, output_file, output_area):
    files = get_file_list(path)
    with open(output_file, "w", encoding="utf-8") as out:
        for f in files:
            h = compute_hash(f)
            if h:
                out.write(f"{os.path.basename(f)}:{h}:{f}\n")
    output_area.insert(tk.END, f"✅ Baseline saved to {output_file}\n")


def load_baseline(control_file):
    baseline = {}
    with open(control_file, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) >= 3:
                filename, file_hash, filepath = parts[0], parts[1], ":".join(parts[2:])
                baseline[filepath] = file_hash
    return baseline


def check_integrity(current_path, control_file, output_area):
    saved = load_baseline(control_file)
    current_files = get_file_list(current_path)
    current_hashes = {}

    for f in current_files:
        h = compute_hash(f)
        if h:
            current_hashes[f] = h

    added = [f for f in current_hashes if f not in saved]
    removed = [f for f in saved if f not in current_hashes]
    modified = [f for f in current_hashes if f in saved and current_hashes[f] != saved[f]]

    output_area.insert(tk.END, "\n🔍 File Integrity Scan Results:\n")
    if not any([added, removed, modified]):
        output_area.insert(tk.END, "✅ All files are intact.\n")
    else:
        if added:
            output_area.insert(tk.END, "\n➕ Added Files:\n")
            for f in added:
                output_area.insert(tk.END, f" - {f}\n")
        if removed:
            output_area.insert(tk.END, "\n➖ Removed Files:\n")
            for f in removed:
                output_area.insert(tk.END, f" - {f}\n")
        if modified:
            output_area.insert(tk.END, "\n🔄 Modified Files:\n")
            for f in modified:
                try:
                    mod_time = datetime.fromtimestamp(os.path.getmtime(f)).strftime('%Y-%m-%d %H:%M:%S')
                    output_area.insert(tk.END, f" - {f} (Last Modified: {mod_time})\n")
                except Exception:
                    output_area.insert(tk.END, f" - {f} (Last Modified: Unknown)\n")


def update_baseline(path, control_file, output_area):
    files = get_file_list(path)
    with open(control_file, "w", encoding="utf-8") as out:
        for f in files:
            h = compute_hash(f)
            if h:
                out.write(f"{os.path.basename(f)}:{h}:{f}\n")
    output_area.insert(tk.END, f"🔄 Baseline updated successfully at {control_file}\n")


# ----- GUI Setup -----

def select_path(entry):
    file = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
    if not file:
        file = filedialog.askdirectory()
    if file:
        entry.delete(0, tk.END)
        entry.insert(0, file)


def select_file(entry):
    file = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if file:
        entry.delete(0, tk.END)
        entry.insert(0, file)


def save_file(entry):
    file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if file:
        entry.delete(0, tk.END)
        entry.insert(0, file)


def main_gui():
    window = tk.Tk()
    window.title("🛡 File Integrity Checker (GUI)")
    window.geometry("900x600")

    # Make grid rows/columns expandable
    window.grid_rowconfigure(3, weight=1)
    for i in range(3):
        window.grid_columnconfigure(i, weight=1)

    # Input Fields
    tk.Label(window, text="📂 File or Directory to Scan:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
    path_entry = tk.Entry(window)
    path_entry.grid(row=0, column=1, sticky="ew", padx=5)
    tk.Button(window, text="Browse", command=lambda: select_path(path_entry)).grid(row=0, column=2, padx=5)

    tk.Label(window, text="📄 Baseline File:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
    file_entry = tk.Entry(window)
    file_entry.grid(row=1, column=1, sticky="ew", padx=5)

    file_button_frame = tk.Frame(window)
    file_button_frame.grid(row=1, column=2, padx=5)
    tk.Button(file_button_frame, text="Open", command=lambda: select_file(file_entry)).pack(side=tk.LEFT, padx=2)
    tk.Button(file_button_frame, text="Save As", command=lambda: save_file(file_entry)).pack(side=tk.LEFT, padx=2)

    # Buttons
    tk.Button(window, text="1 Create Baseline", command=lambda: create_baseline(
        path_entry.get(), file_entry.get(), output_area)).grid(row=2, column=0, pady=10)

    tk.Button(window, text="2 Check Integrity", command=lambda: check_integrity(
        path_entry.get(), file_entry.get(), output_area)).grid(row=2, column=1, pady=10)

    tk.Button(window, text="3 Update Baseline", command=lambda: update_baseline(
        path_entry.get(), file_entry.get(), output_area)).grid(row=2, column=2, pady=10)

    # Output Area
    output_area = scrolledtext.ScrolledText(window)
    output_area.grid(row=3, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

    window.mainloop()


if __name__ == "__main__":
    main_gui()
